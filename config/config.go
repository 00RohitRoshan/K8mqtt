// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2022 wind
// SPDX-FileContributor: wind (573966@qq.com)

package config

import (
	"context"
	tls2 "crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strings"

	"github.com/wind-c/comqtt/v2/cluster/log"
	comqtt "github.com/wind-c/comqtt/v2/mqtt"
	"gopkg.in/yaml.v3"

	// k8e "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	DiscoveryWaySerf uint = iota
	DiscoveryWayMemberlist
)

const (
	RaftImplHashicorp uint = iota
	RaftImplEtcd
)

const (
	StorageWayMemory uint = iota
	StorageWayBolt
	StorageWayBadger
	StorageWayRedis
)

const (
	AuthModeAnonymous uint = iota
	AuthModeUsername
	AuthModeClientid
)

const (
	AuthDSFree uint = iota
	AuthDSRedis
	AuthDSMysql
	AuthDSPostgresql
	AuthDSHttp
)

const (
	BridgeWayNone uint = iota
	BridgeWayKafka
)

var (
	ErrAuthWay     = errors.New("auth-way is incorrectly configured")
	ErrStorageWay  = errors.New("only redis can be used in cluster mode")
	ErrClusterOpts = errors.New("cluster options must be configured")

	ErrAppendCerts      = errors.New("append ca cert failure")
	ErrMissingCertOrKey = errors.New("missing server certificate or private key files")
)

func New() *Config {
	return &Config{}
}

func Load(yamlFile string) (*Config, error) {
	bs, err := os.ReadFile(yamlFile)
	if err != nil {
		return nil, err
	}
	return parse(bs)
}

func getPodIP() []string {
	// creates the in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	start:  // tobe tested
	pods, err := clientset.CoreV1().Pods(os.Getenv("MY_POD_NAMESPACE")).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		panic(err.Error())
	}
	var res []string
	for _, e := range pods.Items {
		name := strings.Split(e.Name, "-")
		if(name[0] == os.Getenv("MY_POD_LABEL")){
			if e.Status.PodIP == ""{
				goto start // tobe tested
			}
			res = append(res, e.Status.PodIP+":7946")
		}
	}
	fmt.Printf("There are %d pods in the cluster\n", len(pods.Items))
	fmt.Println("pod ip :",res)
	fmt.Printf("There are %d members to join\n", len(res))
	// for {
	// 	// get pods in all the namespaces by omitting namespace
	// 	// Or specify namespace to get pods in particular namespace
	// 	pods, err := clientset.CoreV1().Pods(os.Getenv("MY_POD_NAMESPACE")).List(context.TODO(), metav1.ListOptions{
	// 		LabelSelector: os.Getenv("MY_POD_LABEL"),
	// 	})
	// 	if err != nil {
	// 		panic(err.Error())
	// 	}
	// 	fmt.Printf("There are %d pods in the cluster\n", len(pods.Items))
	// 	fmt.Println("pods :", pods)

	// 	// Examples for error handling:
	// 	// - Use helper functions e.g. errors.IsNotFound()
	// 	// - And/or cast to StatusError and use its properties like e.g. ErrStatus.Message
	// 	// _, err = clientset.CoreV1().Pods("default").Get(context.TODO(), "example-xxxxx", metav1.GetOptions{})
	// 	if k8e.IsNotFound(err) {
	// 		fmt.Printf("Pod example-xxxxx not found in default namespace\n")
	// 	} else if statusError, isStatus := err.(*k8e.StatusError); isStatus {
	// 		fmt.Printf("Error getting pod %v\n", statusError.ErrStatus.Message)
	// 	} else if err != nil {
	// 		panic(err.Error())
	// 	} else {
	// 		fmt.Printf("Found example-xxxxx pod in default namespace\n")
	// 	}

	// 	time.Sleep(10 * time.Second)
	// }
	return res
}

func parse(buf []byte) (*Config, error) {
	conf := &Config{}
	err := yaml.Unmarshal(buf, conf)
	if err != nil {
		return nil, err
	}

	if runtime.GOOS[0:3] == "win" {
		// rand.Seed(uint64(time.Now().Unix()))
		// conf.Cluster.NodeName = strconv.Itoa((rand.Intn(999999-100000) + 100000))
		// conf.Cluster.RaftDir = "data/" + conf.Cluster.NodeName
		// Memberst := ""
		// re := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5})`)
		// Members := re.FindAllString(Memberst, -1)
		// // Members := strings.Split(Memberst, ",")
		// fmt.Println("size :", len(Members))
		// conf.Cluster.Members = append(conf.Cluster.Members, Members...)
	} else {
		Memberst := os.Getenv("IP")
		re := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5})`)
		Members := re.FindAllString(Memberst, -1)
		Members = append(Members, getPodIP()...)
		fmt.Println("size :", len(Members))
		conf.Cluster.Members = append(conf.Cluster.Members, Members...)

		conf.Cluster.BindAddr = os.Getenv("MY_POD_IP")
		// conf.Cluster.AdvertiseAddr = os.Getenv("MY_POD_IP")
		conf.Cluster.NodeName = os.Getenv("MY_POD_NAME")
		conf.Cluster.RaftDir = "data/" + conf.Cluster.NodeName
		if os.Getenv("RaftBootstrap") == "true" {
			conf.Cluster.RaftBootstrap = true
		} else {
			conf.Cluster.RaftBootstrap = false
		}
		conf.Cluster.AdvertiseAddr = os.Getenv("advertise-addr")
	}
	// // service := strings.Split(os.Getenv("MY_POD_NAME"), "-")
	// // Member := service[0] + "." + os.Getenv("MY_POD_NAMESPACE") + ".svc.cluster.local:" + strconv.Itoa(conf.Cluster.BindPort)
	// Member := os.Getenv("IP") + strconv.Itoa(conf.Cluster.BindPort)
	// conf.Cluster.Members = append(conf.Cluster.Members, Member)
	// // conf.Cluster.BindAddr = service[0] + "." + os.Getenv("MY_POD_NAMESPACE") + ".svc.cluster.local" //service or podIP
	fmt.Println("cluster : ", conf.Cluster)

	return conf, nil
}

type Config struct {
	StorageWay  uint        `yaml:"storage-way"`
	StoragePath string      `yaml:"storage-path"`
	BridgeWay   uint        `yaml:"bridge-way"`
	BridgePath  string      `yaml:"bridge-path"`
	Auth        auth        `yaml:"auth"`
	Mqtt        mqtt        `yaml:"mqtt"`
	Cluster     Cluster     `yaml:"cluster"`
	Redis       redis       `yaml:"redis"`
	Log         log.Options `yaml:"log"`
	PprofEnable bool        `yaml:"pprof-enable"`
}

type auth struct {
	Way           uint   `yaml:"way"`
	Datasource    uint   `yaml:"datasource"`
	ConfPath      string `yaml:"conf-path"`
	BlacklistPath string `yaml:"blacklist-path"`
}

type mqtt struct {
	TCP     string         `yaml:"tcp"`
	WS      string         `yaml:"ws"`
	HTTP    string         `yaml:"http"`
	Tls     tls            `yaml:"tls"`
	Options comqtt.Options `yaml:"options"`
}

type tls struct {
	CACert     string `yaml:"ca-cert"`
	ServerCert string `yaml:"server-cert"`
	ServerKey  string `yaml:"server-key"`
}

type redisOptions struct {
	Addr     string `json:"addr" yaml:"addr"`
	Username string `json:"username" yaml:"username"`
	Password string `json:"password" yaml:"password"`
	DB       int    `json:"db" yaml:"db"`
}

type redis struct {
	HPrefix string `json:"prefix" yaml:"prefix"`
	Options redisOptions
}

type Cluster struct {
	DiscoveryWay         uint              `yaml:"discovery-way"  json:"discovery-way"`
	NodeName             string            `yaml:"node-name" json:"node-name"`
	BindAddr             string            `yaml:"bind-addr" json:"bind-addr"`
	BindPort             int               `yaml:"bind-port" json:"bind-port"`
	AdvertiseAddr        string            `yaml:"advertise-addr" json:"advertise-addr"`
	AdvertisePort        int               `yaml:"advertise-port" json:"advertise-port"`
	Members              []string          `yaml:"members" json:"members"`
	QueueDepth           int               `yaml:"queue-depth" json:"queue-depth"`
	Tags                 map[string]string `yaml:"tags" json:"tags"`
	RaftImpl             uint              `yaml:"raft-impl" json:"raft-impl"`
	RaftPort             int               `yaml:"raft-port" json:"raft-port"`
	RaftDir              string            `yaml:"raft-dir" json:"raft-dir"`
	RaftBootstrap        bool              `yaml:"raft-bootstrap" json:"raft-bootstrap"`
	RaftLogLevel         string            `yaml:"raft-log-level" json:"raft-log-level"`
	GrpcEnable           bool              `yaml:"grpc-enable" json:"grpc-enable"`
	GrpcPort             int               `yaml:"grpc-port" json:"grpc-port"`
	InboundPoolSize      int               `yaml:"inbound-pool-size" json:"inbound-pool-size"`
	OutboundPoolSize     int               `yaml:"outbound-pool-size" json:"outbound-pool-size"`
	InoutPoolNonblocking bool              `yaml:"inout-pool-nonblocking" json:"inout-pool-nonblocking"`
	NodesFileDir         string            `yaml:"nodes-file-dir" json:"nodes-file-dir"`
}

func GenTlsConfig(conf *Config) (*tls2.Config, error) {
	if conf.Mqtt.Tls.ServerKey == "" && conf.Mqtt.Tls.ServerCert == "" {
		return nil, nil
	}

	if conf.Mqtt.Tls.ServerKey == "" || conf.Mqtt.Tls.ServerCert == "" {
		return nil, ErrMissingCertOrKey
	}

	cert, err := tls2.LoadX509KeyPair(conf.Mqtt.Tls.ServerCert, conf.Mqtt.Tls.ServerKey)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls2.Config{
		MinVersion:   tls2.VersionTLS12,
		Certificates: []tls2.Certificate{cert},
	}

	// enable bidirectional authentication
	if conf.Mqtt.Tls.CACert != "" {
		pem, err := os.ReadFile(conf.Mqtt.Tls.CACert)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, ErrAppendCerts
		}

		tlsConfig.RootCAs = pool
		tlsConfig.ClientCAs = pool
		tlsConfig.ClientAuth = tls2.RequireAndVerifyClientCert
	}

	return tlsConfig, nil
}
