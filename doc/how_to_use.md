# How to use ontlogin sdk go

## 1. 介绍

略



## 2. 在项目中集成ontlogin sdk

在项目中集成ontlogin sdk

只需要以下步骤：

1. 初始化sdk

2. 新增2个api:  

   1. requestChallenge: 用于请求服务的的挑战内容

   2. submitChallenge:提交对挑战内容的签名，以及服务端要求的VP（如果有）

      

3. 根据业务需求，映射DID和既有的用户ID，解析并保存VP中的数据。

### 2.1 集成的详细流程

ontlong-sdk-go : https://github.com/ontology-tech/ontlogin-sdk-go

简单起见，本示例使用 go-chi  https://github.com/go-chi/chi 创建Restful 后台服务.

示例源码：https://github.com/ontology-tech/ontlogin-sample-go



1. 在go.mod 中加入引用：

```
require (
	...
	github.com/ontology-tech/ontlogin-sdk-go latest
)
```



2. 在main.go 中加入申请挑战和提交挑战的rest 接口

```go
package main

import (
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"ontlogin-sample/auth"
	"ontlogin-sample/service"
)


func main() {
	r := chi.NewRouter()
	service.InitService()
	r.Use(cors.Handler(cors.Options{
		// AllowedOrigins:   []string{"https://foo.com"}, // Use this to allow specific origin hosts
		AllowedOrigins: []string{"*"},
		// AllowOriginFunc:  func(r *http.Request, origin string) bool { return true },
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		//AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		AllowedHeaders:   []string{"Authorization", "Content-Length", "X-CSRF-Token", "Token", "session", "X_Requested_With", "Accept", "Origin", "Host", "Connection", "Accept-Encoding", "Accept-Language", "DNT", "X-CustomHeader", "Keep-Alive", "User-Agent", "X-Requested-With", "If-Modified-Since", "Cache-Control", "Content-Type", "Pragma"},
		ExposedHeaders:   []string{"Content-Length", "token", "Access-Control-Allow-Origin", "Access-Control-Allow-Headers", "Cache-Control", "Content-Language", "Content-Type", "Expires", "Last-Modified", "Pragma", "FooBar"},
		AllowCredentials: false,
		MaxAge:           172800, // Maximum value not ignored by any of major browsers
		//Debug:true,
	}))
	r.Use(middleware.Logger)
	r.Use(auth.Middleware())

	r.Post("/requestChallenge", service.RequestChallenge)
	r.Post("/submitChallenge",service.Login)
	r.Get("/afterLogin",service.AfterLogin)
	log.Fatal(http.ListenAndServe(":3000", r))
}

```

说明：

```go
service.InitService()
```

初始化服务，保护对ontlogin sdk 的初始化，后面有详细的解释



```go
r.Use(cors.Handler(cors.Options{
		// AllowedOrigins:   []string{"https://foo.com"}, // Use this to allow specific origin hosts
		AllowedOrigins: []string{"*"},
		// AllowOriginFunc:  func(r *http.Request, origin string) bool { return true },
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		//AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		AllowedHeaders:   []string{"Authorization", "Content-Length", "X-CSRF-Token", "Token", "session", "X_Requested_With", "Accept", "Origin", "Host", "Connection", "Accept-Encoding", "Accept-Language", "DNT", "X-CustomHeader", "Keep-Alive", "User-Agent", "X-Requested-With", "If-Modified-Since", "Cache-Control", "Content-Type", "Pragma"},
		ExposedHeaders:   []string{"Content-Length", "token", "Access-Control-Allow-Origin", "Access-Control-Allow-Headers", "Cache-Control", "Content-Language", "Content-Type", "Expires", "Last-Modified", "Pragma", "FooBar"},
		AllowCredentials: false,
		MaxAge:           172800, // Maximum value not ignored by any of major browsers
		//Debug:true,
	}))
```

处理跨域问题

```go
r.Use(auth.Middleware())
```

应用 登录权限检测， 后面有详细解释

```go
	r.Post("/requestChallenge", service.RequestChallenge)           //申请挑战
	r.Post("/submitChallenge",service.Login)                        //提交挑战
	r.Get("/afterLogin",service.AfterLogin)                         //其他业务逻辑
```

定义Restful api的处理函数



3. service.go , service 主要用于处理Restful 的请求

```go
package service

import (
	"encoding/json"
	"fmt"
	"github.com/ontology-tech/ontlogin-sdk-go/did"
	"github.com/ontology-tech/ontlogin-sdk-go/did/ont"
	"github.com/ontology-tech/ontlogin-sdk-go/modules"
	ontloginsdk "github.com/ontology-tech/ontlogin-sdk-go/sdk"
	"net/http"

	"github.com/google/uuid"

	"ontlogin-sample/auth"
	"ontlogin-sample/jwt"
)

var loginsdk *ontloginsdk.OntLoginSdk
var mapstore map[string]string

func InitService() {
	mapstore = make(map[string]string)

	vcfilters := make(map[string][]*modules.VCFilter)
	vcfilters[modules.ACTION_REGISTER] = []*modules.VCFilter{
		{Type: "EmailCredential", Required: true, TrustRoots: []string{"did:ont:ssssss"}},
	}
	conf := &ontloginsdk.SDKConfig{
		Chain: []string{"ont"},
		Alg:   []string{"ES256"},
		ServerInfo: &modules.ServerInfo{
			Name:               "testServcer",
			Icon:               "http://somepic.jpg",
			Url:                "https://ont.io",
			Did:                "did:ont:sampletest",
			VerificationMethod: "",
		},
		VCFilters: vcfilters,
	}

	resolvers := make(map[string]did.DidResolver)
	ontresolver, err := ont.NewOntResolver(false, "http://polaris2.ont.io:20336", "52df370680de17bc5d4262c446f102a0ee0d6312", "./wallet.dat", "123456")
	if err != nil {
		panic(err)
	}
	resolvers["ont"] = ontresolver
	loginsdk, err = ontloginsdk.NewOntLoginSdk(conf, resolvers, GenUUID, CheckNonce)
	if err != nil {
		panic(err)
	}
}

func RequestChallenge(writer http.ResponseWriter, request *http.Request){
	cr := &modules.ClientHello{}
	writer.Header().Set("Content-Type", "application/json")
	err := json.NewDecoder(request.Body).Decode(&cr)
	if err != nil {
		fmt.Printf("err:%s\n",err.Error())
		writer.Write([]byte(err.Error()))
		return
	}

	serverHello,err := loginsdk.GenerateChallenge(cr)
	if err!= nil{
		fmt.Printf("err:%s\n",err.Error())
		writer.Write([]byte(err.Error()))
		return
	}

	bts,_:=json.Marshal(serverHello)

	writer.Write(bts)

}

func Login(writer http.ResponseWriter, request *http.Request){
	lr := &modules.ClientResponse{}
	writer.Header().Set("Content-Type", "application/json")

	err := json.NewDecoder(request.Body).Decode(&lr)

	if err != nil {
		fmt.Printf("err:%s\n",err.Error())
		writer.Write([]byte(err.Error()))
		return
	}

	err = loginsdk.ValidateClientResponse(lr)
	if err != nil {
		fmt.Printf("err:%s\n",err.Error())
		writer.Write([]byte(err.Error()))
		return
	}

	s ,err:= jwt.GenerateToken(lr.Did)

	writer.Write([]byte(s))

}

func AfterLogin(writer http.ResponseWriter, request *http.Request) {
	if err := auth.CheckLogin(request.Context()); err != nil {
		fmt.Printf("err:%s\n", err.Error())
		writer.Write([]byte("please login first"))
		return
	}
	writer.Write([]byte("normal business process"))
}


func GenUUID()string{
	uuid,err := uuid.NewUUID()
	if err != nil{
		fmt.Printf("uuid failed:%s\n",err.Error())
		return ""
	}
	mapstore[uuid.String()] = "ok"
	return uuid.String()
}

func CheckNonce(nonce string)error{
	if _,ok:=mapstore[nonce];!ok{
		return fmt.Errorf("no nonce found")
	}
	return nil
}
```

初始化service:

```go
func InitService(){
	mapstore = make(map[string]string)  //用于存储生成的挑战uuid，实际的项目中可以保存在数据库，redis,或者cache中
    vcfilters := make(map[string][]*modules.VCFilter)
    
    //配置不同的actionType 下的VC filter
	vcfilters[modules.ACTION_REGISTER] = []*modules.VCFilter{
		{Type: "EmailCredential",  //VC type
         Required: true,           //是否必须 
         TrustRoots: []string{"did:ont:ssssss"}，//发行方的DID
        },
	}
    //sdk 需要的服务端配置信息，可以从配置文件等中读取
	conf := &ontloginsdk.SDKConfig{
		Chain:[]string{"ont"},         //支持的链的名称， 如eth, ont, bsc等， 需要实现对应resolver
		Alg:[]string{"ES256"},         //支持的签名算法 
		ServerInfo:&modules.ServerInfo{                       //服务器的信息
			Name:               "testServcer",                
			Icon:               "http://somepic.jpg",
			Url:                "https://ont.io",
			Did:                "did:ont:sampletest",         //服务的DID 
			VerificationMethod: "",
		},
		Vcfilters:vcfilters ,                                //服务端在注册时要求客户端提供的VC类型
		
		
	}

	resolvers := make(map[string]did.DidResolver)             //初始化链的resolver
    //以ontology 为例，参数说明
    //1. doubleDirection bool: 是否需要双向挑战认证
    //2. ontology 节点rpc的服务地址
    //3. did 的合约地址，如果doubleDirection 为false,可以为空
    //4. ontology的钱包地址，如果doubleDirection 为false,可以为空
    //5. 钱包密码，如果doubleDirection 为false,可以为空
    
	ontresolver,err := ont.NewOntResolver(false,"http://polaris2.ont.io:20336","52df370680de17bc5d4262c446f102a0ee0d6312","./wallet.dat","123456")
	if err != nil {
		panic(err)
	}
	resolvers["ont"]=ontresolver
    //除了config，和resolver,sdk 还需要传入两个函数
    //1. UUID 生成函数 func()string
    //2. 验证Nonce(UUID)是否存在与数据库/redis/缓存中的函数 func(string)error
	loginsdk,err = ontloginsdk.NewOntLoginSdk(conf,resolvers,GenUUID,CheckNonce)
	if err != nil {
		panic(err)
	}
}

```

处理申请挑战

```go

func RequestChallenge(writer http.ResponseWriter, request *http.Request){
    //处理客户端请求
	cr := &modules.ClientHello{}
	writer.Header().Set("Content-Type", "application/json")
	err := json.NewDecoder(request.Body).Decode(&cr)
	if err != nil {
		fmt.Printf("err:%s\n",err.Error())
		writer.Write([]byte(err.Error()))
		return
	}
	//调用sdk生成挑战
	serverHello,err := loginsdk.GenerateChallenge(cr)
	if err!= nil{
		fmt.Printf("err:%s\n",err.Error())
		writer.Write([]byte(err.Error()))
		return
	}
	
    //返回挑战
	bts,_:=json.Marshal(serverHello)
	writer.Write(bts)
}

```

处理客户端的签名挑战

```go
func Login(writer http.ResponseWriter, request *http.Request){
	lr := &modules.ClientResponse{}
	writer.Header().Set("Content-Type", "application/json")

	err := json.NewDecoder(request.Body).Decode(&lr)

	if err != nil {
		fmt.Printf("err:%s\n",err.Error())
		writer.Write([]byte(err.Error()))
		return
	}

	err = loginsdk.ValidateClientResponse(lr)
	if err != nil {
		fmt.Printf("err:%s\n",err.Error())
		writer.Write([]byte(err.Error()))
		return
	}
    
    //用户的挑战验证通过
    //下面可以依据系统或业务来做不同的处理
    //如本示例使用JWT作为之后的权限验证

	s ,err:= jwt.GenerateToken(lr.Did)
	writer.Write([]byte(s))

}

```

处理VP

如果要求客户端在挑战中包含所需要的VC，由于VC的格式并不固定，所以sdk仅提供从VP中抽取VC的JSON格式的文本的功能

```
 GetCredentailJson(chain, presentation string) ([]string, error)
```

服务端可以根据约定好的格式来解析VC，做后续的业务处理

