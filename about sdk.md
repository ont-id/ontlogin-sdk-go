# ontlogin-sdk-go
## API instruction

### 1. NewOntLoginSdk

创建 OntLoginSdk实例

parameters:

```
conf *SDKConfig                               //sdk configuartion

processors map[string]did.DidProcessor        //did processer map 

nonceFunc func(int) string                    //function to generate random nonce

getActionByNonce func(string) (int,error)     //get action by nonce
```



return :

```*OntLoginSdk, error```



说明：

SDKConfig：

```
type SDKConfig struct {
	Chain      []string                       //支持的链的名称 如“ONT”，“ETH“，”BSC“等
	Alg        []string                       //支持的签名算法  "ES256","Ed25519" 等
	ServerInfo *modules.ServerInfo            //服务器信息配置
	VCFilters  map[int][]*modules.VCFilter    //认证/授权所需要的Verifiable Credential的过滤器信息
}
```

```
type ServerInfo struct {
	Name               string `json:"name"`                             //服务器名称
	Icon               string `json:"icon,omitempty"`                   //图标  （可选）
	Url                string `json:"url"`                              //服务URL 
	Did                string `json:"did,omitempty"`                    //服务器DID（可选）
	VerificationMethod string `json:"verificationMethod,omitempty"`     //验证方法 （可选）
}
```

```
type VCFilter struct {
	Type       string   `json:"type"`                                   //VC的类型 如“DegreeCredential”等
	Express    []string `json:"express,omitempty"`                      //零知识证明表达式列表
	TrustRoots []string `json:"trust_roots"`                            //信任的VC发行方DID列表
	Required   bool     `json:"required"`                               //是否必需   
}
```



## 2. GenerateChallenge

生成挑战

param:

```
type ClientHello struct {
	Ver             string           `json:"ver"`                       //版本号
	Type            string           `json:"type"`                      //固定为“ClientHello“
	Action          int              `json:"action"`                    //0：认证 ， 1：授权
	ClientChallenge *ClientChallenge `json:"ClientChallenge,omitempty"` //客户端挑战，用于双向验证（可选）
}
```

return: (*modules.ServerHello, error)

```
type ServerHello struct {
	Ver         string       `json:"ver"`                        //版本号
	Type        string       `json:"type"`						 //固定为“ServerHello“
	Nonce       string       `json:"nonce"`                      //随机nonce字符串
	Server      *ServerInfo  `json:"server"`                     //服务器信息 
	Chain       []string     `json:"chain"`                      //支持的链名称列表 
	Alg         []string     `json:"alg"`                        //支持的签名算法列表
	VCFilters   []*VCFilter  `json:"VCFilters,omitempty"`        //VC的过滤列表（可选）  
	ServerProof *ServerProof `json:"ServerProof,omitempty"`      //服务器端证明，用于双向验证（可选）
	Extension   *Extension   `json:"extension,omitempty"`        //扩展字段（可选）
}
```



## 3. ValidateClientResponse

验证客户端响应

param:

```
type ClientResponse struct {
	Ver   string   `json:"ver"`					//版本号
	Type  string   `json:"type"`				//固定为“ClientResponse“
	Did   string   `json:"did"`					//用户DID
	Nonce string   `json:"nonce"`               //服务器生成的随机nonce字符串
	Proof *Proof   `json:"proof"`               //客户端签名信息
	VPs   []string `json:"VPs,omitempty"`       //verifiable presenation 列表（可选）
}
```

return:

error

说明：

```
type Proof struct {
	Type               string `json:"type"`               //签名算法
	VerificationMethod string `json:"verificationMethod"` //did & key index 如："did:ont:alice#key-1"
	Created            uint64 `json:"created"`            //时间戳unix
	Value              string `json:"value"`              //签名字符串HEX
}
```



验证逻辑：

1. 验证输入参数合法性
2. 验证nonce是否为服务端生成
3. 验证客户端签名
4. 验证所有的VP及其包含的VC的合法性
5. 验证所有必需的VC是否都已经提供



## 4. GetCredentialJson

取得VP中所有VC的JSON字符串

param:

```
chain  ,      //链的名称
presentation，//VP 的字符串
```

return:

```
[]string,     //VC的JSON 字符串
error         
```

## 错误信息表

```buildoutcfg
	ERR_WRONG_VERSION               = "ERR_WRONG_VERSION"
	ERR_TYPE_NOT_SUPPORTED          = "ERR_TYPE_NOT_SUPPORTED"
	ERR_CHAIN_NOT_SUPPORTED         = "ERR_CHAIN_NOT_SUPPORTED"
	ERR_CLIENT_UUID_NOT_GENERATED   = "ERR_CLIENT_UUID_NOT_GENERATED"
	ERR_ACTION_NOT_SUPPORTED        = "ERR_ACTION_NOT_SUPPORTED"
	ERR_UNDEFINED                   = "ERR_UNDEFINED"
	ERR_INVALID_DID_FORMAT          = "ERR_INVALID_DID_FORMAT"
	ERR_DID_NOT_MATCH               = "ERR_DID_NOT_MATCH"
	ERR_NONCE_IS_NOT_EXIST          = "ERR_NONCE_IS_NOT_EXIST"
	ERR_VERIFYMETHOD_FORMAT_INVALID = "ERR_VERIFYMETHOD_FORMAT_INVALID"
	ERR_MARSHAL_MSG                 = "ERR_MARSHAL_MSG"
	ERR_DECODE_SIG                  = "ERR_DECODE_SIG"

	ERR_VERIFY_JWT_ISSUER_SIG_FAILED     = "ERR_VERIFY_JWT_ISSUER_SIG_FAILED"
	ERR_JWTPRESENTATION_DECODE_FAILED    = "ERR_JWTPRESENTATION_DECODE_FAILED"
	ERR_VERIFY_PRESENTATION_PROOF_FAILED = "ERR_VERIFY_PRESENTATION_PROOF_FAILED"
	ERR_JSON_TO_JWT_FAILED               = "ERR_JSON_TO_JWT_FAILED"
	ERR_REQUIRED_CREDENTIAL_NOT_EXIST    = "ERR_REQUIRED_CREDENTIAL_NOT_EXIST:%s"
	ERR_VERIFY_JWT_ISSUE_DATE_FAILED     = "ERR_VERIFY_JWT_ISSUE_DATE_FAILED"
	ERR_VERIFY_JWT_EXPIRE_DATE_FAILED    = "ERR_VERIFY_JWT_EXPIRE_DATE_FAILED"
	ERR_VERIFY_JWT_CREDITABLE_DID_FAILED = "ERR_VERIFY_JWT_CREDITABLE_DID_FAILED"
	ERR_VERIFY_JWT_STATUS_FAILED         = "ERR_VERIFY_JWT_STATUS_FAILED"

	ERR_ONT_SDK_EMPTY                = "ERR_ONT_SDK_EMPTY"
	ERR_PUBKEY_EMPTY                 = "ERR_PUBKEY_EMPTY"
	ERR_DID_CONTRACT_EMPTY           = "ERR_DID_CONTRACT_EMPTY"
	ERR_DID_CONTRACT_ADDRESS_INVALID = "ERR_DID_CONTRACT_ADDRESS_INVALID"
	ERR_OPEN_WALLET_FAILED           = "ERR_OPEN_WALLET_FAILED"
	ERR_OPEN_ACCOUNT_FAILED          = "ERR_OPEN_ACCOUNT_FAILED"
```
