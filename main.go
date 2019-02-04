package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/elb"
	"github.com/aws/aws-sdk-go-v2/service/route53"
)

type Service struct {
	Metadata struct {
		Annotations struct {
			DomainName string `json:"domainName"`
			Internal   string `json:"service.beta.kubernetes.io/aws-load-balancer-internal"`
		} `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
	} `json:"spec"`

	Status struct {
		LoadBalancer struct {
			Ingress []struct {
				Hostname string `json:"hostname"`
			} `json:"ingress"`
		} `json:"loadBalancer"`
	} `json:"status"`
}

type ServicesResponse struct {
	Items []*Service `json:"items"`
}

type key struct {
	domainname string
	private    bool
}

type awssvc struct {
	route53 *route53.Route53
	client  *http.Client
	elb     *elb.ELB
}

func withretry(f func() error) error {
	var err error
	var i uint
	for i = 0; i < 10; i++ {
		if err = f(); err == nil {
			return nil
		}

		if !aws.IsErrorRetryable(err) && !aws.IsErrorThrottle(err) {
			return err
		}
		time.Sleep(time.Second + time.Millisecond*400*(1<<i))
		fmt.Fprintf(os.Stderr, "%v\n", err)
	}
	return err
}

func processRecords(records []route53.ResourceRecordSet, actual map[key]string, isPrivate bool) {
	for _, record := range records {
		if record.Type == route53.RRTypeA {
			if record.AliasTarget == nil {
				//fmt.Println(record.String())
				continue
			}
			target := stripLastDot(*record.AliasTarget.DNSName)
			name := stripLastDot(*record.Name)

			actual[key{name, isPrivate}] = target
		}
	}
}

func (s *awssvc) UpdateRecord(zone, dnsname, target, targetzone string) error {
	parts := strings.Split(zone, "/")
	zone = parts[len(parts)-1]
	return withretry(func() error {
		_, err := s.route53.ChangeResourceRecordSetsRequest(&route53.ChangeResourceRecordSetsInput{
			HostedZoneId: aws.String(zone),
			ChangeBatch: &route53.ChangeBatch{
				Changes: []route53.Change{
					route53.Change{
						Action: "UPSERT",
						ResourceRecordSet: &route53.ResourceRecordSet{
							Type: route53.RRTypeA,
							Name: aws.String(dnsname + "."),
							AliasTarget: &route53.AliasTarget{
								DNSName:              aws.String(target + "."),
								HostedZoneId:         aws.String(targetzone),
								EvaluateTargetHealth: aws.Bool(false),
							},
						},
					},
				},
			},
		}).Send()
		return err
	})
}

func (s *awssvc) GetExpectedRecordSets() (map[key]string, error) {
	req, err := http.NewRequest("GET", "https://kubernetes.default.svc.cluster.local/api/v1/services", nil)
	if err != nil {
		return nil, err
	}

	token, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, err
	}
	req.Header.Add("authorization", "Bearer "+string(token))

	res, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	services := ServicesResponse{}
	if err := json.Unmarshal(b, &services); err != nil {
		return nil, err
	}

	expected := map[key]string{}

	for _, service := range services.Items {
		private := service.Metadata.Annotations.Internal != ""
		if len(service.Status.LoadBalancer.Ingress) > 0 {
			if len(service.Status.LoadBalancer.Ingress) != 1 {
				panic("unexpected ingress length")
			}

			domainname := service.Metadata.Annotations.DomainName
			if domainname == "" {
				continue
			}
			elb := service.Status.LoadBalancer.Ingress[0].Hostname
			if elb == "" {
				continue
			}
			expected[key{domainname, private}] = elb
		}
	}

	return expected, nil
}

func (s *awssvc) GetZones() (map[key]string, error) {
	var hostedzones []route53.HostedZone
	err := withretry(func() error {
		hz, err := s.route53.ListHostedZonesRequest(&route53.ListHostedZonesInput{}).Send()
		if err != nil {
			return err
		}
		hostedzones = hz.HostedZones
		return nil
	})
	if err != nil {
		return nil, err
	}

	ret := map[key]string{}
	for _, zone := range hostedzones {
		domain := stripLastDot(*zone.Name)
		k := key{domainname: domain, private: *zone.Config.PrivateZone}
		ret[k] = *zone.Id
	}
	return ret, nil
}

func (s *awssvc) GetRecordSets(zones map[key]string) (map[key]string, error) {

	actual := map[key]string{}

	for k, zone := range zones {
		keepgoing := true
		isPrivate := k.private
		id := aws.String(zone)
		var records *route53.ListResourceRecordSetsOutput

		for keepgoing {
			input := &route53.ListResourceRecordSetsInput{
				HostedZoneId: id,
			}

			if records != nil {
				input.StartRecordName = records.NextRecordName
				input.StartRecordType = records.NextRecordType
			}

			err := withretry(func() error {
				var err error
				records, err = s.route53.ListResourceRecordSetsRequest(input).Send()
				if err != nil {
					return err
				}
				return nil
			})
			if err != nil {
				return nil, err
			}

			processRecords(records.ResourceRecordSets, actual, isPrivate)

			keepgoing = records.IsTruncated != nil && *records.IsTruncated == true
		}
	}

	return actual, nil
}

func (s *awssvc) GetLoadBalancers() (map[string]string, error) {
	ret := map[string]string{}
	var next string
	for {
		var out *elb.DescribeLoadBalancersOutput
		input := &elb.DescribeLoadBalancersInput{}
		if next != "" {
			input.Marker = aws.String(next)
		}

		err := withretry(func() error {
			var err error
			out, err = s.elb.DescribeLoadBalancersRequest(input).Send()
			return err
		})
		if err != nil {
			return nil, err
		}

		for _, lb := range out.LoadBalancerDescriptions {
			zone := *lb.CanonicalHostedZoneNameID
			domain := *lb.DNSName
			ret[domain] = zone
		}

		if out.NextMarker == nil {
			break
		}
		next = *out.NextMarker
		if next == "" {
			break
		}
	}

	return ret, nil

}

func main() {

	cfg, err := external.LoadDefaultAWSConfig()
	if err != nil {
		panic(err)
	}

	client, err := newClient()
	if err != nil {
		panic(err)
	}

	svc := awssvc{
		route53: route53.New(cfg),
		elb:     elb.New(cfg),
		client:  client,
	}

	zones, err := svc.GetZones()
	if err != nil {
		panic(err)
	}

	for k, zone := range zones {
		fmt.Println(k, zone)
	}

	actual, err := svc.GetRecordSets(zones)
	if err != nil {
		panic(err)
	}

	loadbalancers, err := svc.GetLoadBalancers()
	if err != nil {
		panic(err)
	}

	for {
		expected, err := svc.GetExpectedRecordSets()
		if err != nil {
			panic(err)
		}

		fmt.Fprintln(os.Stderr, "comparing expected to actual records")
		for k, target := range expected {
			pre := ""
			if target != actual[k] {
				tld := getTLD(k.domainname)
				zone, ok := zones[key{domainname: tld, private: k.private}]
				if !ok {
					fmt.Printf("missing zone for domain: %s\n", k.domainname)
					continue
				}

				targetzone, ok := loadbalancers[target]
				if !ok {
					fmt.Printf("missing target zone for elb: %s\n", target)
					loadbalancers, err = svc.GetLoadBalancers()
					if err != nil {
						panic(err)
					}
					continue
				}

				fmt.Fprintf(os.Stderr, "updating record for: %s in zone: %s\n", k.domainname, zone)
				err := svc.UpdateRecord(zone, k.domainname, target, targetzone)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
				} else {
					actual[k] = target
				}
				pre = "NEEDS UPDATE "
			}
			fmt.Printf("%s %s (private: %t) expected: %s, actual: %s\n", pre, k.domainname, k.private, target, actual[k])
		}

		time.Sleep(time.Second * 40)
	}

}

func newClient() (*http.Client, error) {
	cert, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cert) {
		return nil, fmt.Errorf("error appending cert to pool")
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    pool,
			},
		},
	}

	return client, nil
}

func stripLastDot(target string) string {
	if target[len(target)-1] != '.' {
		panic("expected ., got: " + target)
	}
	return target[:len(target)-1]
}

func getTLD(target string) string {
	parts := strings.Split(target, ".")
	if len(parts) < 3 {
		panic("expected at least 3 parts in domain")
	}

	tld := parts[len(parts)-2:]
	return strings.Join(tld, ".")
}
