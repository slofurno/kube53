package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/elbv2"
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

func main() {

	b, _ := ioutil.ReadFile("./services.json")
	services := ServicesResponse{}
	err := json.Unmarshal(b, &services)
	if err != nil {
		panic(err)
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
			fmt.Println(private, domainname, elb)
			expected[key{domainname, private}] = elb
		}
	}

	cfg, err := external.LoadDefaultAWSConfig()
	if err != nil {
		panic(err)
	}

	elbsvc := elbv2.New(cfg)

	lbs, err := elbsvc.DescribeLoadBalancersRequest(&elbv2.DescribeLoadBalancersInput{}).Send()
	if err != nil {
		panic(err)
	}

	fmt.Println(len(lbs.LoadBalancers))
	//for _, lb := range lbs.LoadBalancers {
	//	fmt.Println(lb.String())
	//}

	svc := route53.New(cfg)
	hz, err := svc.ListHostedZonesRequest(&route53.ListHostedZonesInput{}).Send()
	if err != nil {
		panic(err)
	}

	actual := map[key]string{}
	for _, zone := range hz.HostedZones {
		records, err := svc.ListResourceRecordSetsRequest(&route53.ListResourceRecordSetsInput{
			HostedZoneId: zone.Id,
		}).Send()
		if err != nil {
			panic(err)
		}

		isPrivate := *zone.Config.PrivateZone

		processRecords := func(records []route53.ResourceRecordSet) {
			for _, record := range records {
				if record.Type == route53.RRTypeA {
					name := *record.Name
					if record.AliasTarget == nil {
						fmt.Println(record.String())
						continue
					}
					target := *record.AliasTarget.DNSName

					if name[len(name)-1] != '.' {
						panic("expected ., got: " + name)
					}

					if target[len(target)-1] != '.' {
						panic("expected ., got: " + target)
					}
					target = target[:len(target)-1]
					name = name[:len(name)-1]
					fmt.Println(*zone.Id, isPrivate, name, target)

					actual[key{name, isPrivate}] = target
				}
			}
		}

		processRecords(records.ResourceRecordSets)
		time.Sleep(time.Second)

		if records.IsTruncated != nil && *records.IsTruncated == true {
			fmt.Println("TRUNCATED")
			records, err := svc.ListResourceRecordSetsRequest(&route53.ListResourceRecordSetsInput{
				HostedZoneId:    zone.Id,
				StartRecordName: records.NextRecordName,
				StartRecordType: records.NextRecordType,
			}).Send()
			if err != nil {
				panic(err)
			}
			processRecords(records.ResourceRecordSets)

		}
	}

	for k, target := range expected {
		pre := ""
		if target != actual[k] {
			pre = "NEEDS UPDATE "
		}
		fmt.Printf("%s %s (private: %t) expected: %s, actual: %s\n", pre, k.domainname, k.private, target, actual[k])
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
