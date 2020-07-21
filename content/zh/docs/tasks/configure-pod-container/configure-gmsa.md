{{% capture overview %}}
{{< feature-state for_k8s_version="v1.16" state="beta" >}}
<!--
This page shows how to configure Group Managed Service Accounts (GMSA) for Pods and containers that will run on Windows nodes. Group Managed Service Accounts are a specific type of Active Directory account that provides automatic password management, simplified service principal name (SPN) management, and the ability to delegate the management to other administrators across multiple servers.
-->
这篇文章介绍了如何为 Windows 节点上运行的 Pods 和容器配置 Group Managed Service Accounts（GMSA）。Group Managed Service Accounts 是 Active Directory 帐户的一种特定类型，它提供自动密码管理、简化的服务主体名称（SPN）管理以及将管理委派给跨服务器的其他管理员的功能。
<!--
In Kubernetes, GMSA credential specs are configured at a Kubernetes cluster-wide scope as Custom Resources. Windows Pods, as well as individual containers within a Pod, can be configured to use a GMSA for domain based functions (e.g. Kerberos authentication) when interacting with other Windows services. As of v1.16, the Docker runtime supports GMSA for Windows workloads.
-->
在 Kubernetes 中，GMSA 凭据规范在 Kubernetes 集群范围内配置为“自定义资源”。 在与其他 Windows 服务进行交互时，可以将 Windows Pods 以及 Pod 中的各个容器配置为GMSA 用于基于域的功能（例如 Kerberos 身份验证）。从 v1.16 开始，Docker 运行时支持 Windows 工作负载的 GMSA。
{{% /capture %}}
{{% capture prerequisites %}}
<!--
You need to have a Kubernetes cluster and the kubectl command-line tool must be configured to communicate with your cluster. The cluster is expected to have Windows worker nodes. This section covers a set of initial steps required once for each cluster:
-->
您需要一个 Kubernetes 集群，并且必须配置 kubectl 命令行工具与您的集群通信。该群集应具有 Windows 工作程序节点。本节介绍了每个集群所需的一组初始步骤：
<!--
WindowsGMSA feature gate
The WindowsGMSA feature gate (required to pass down GMSA credential specs from the pod specs to the container runtime) is enabled by default on the API server and the kubelet. See Feature Gates for an explanation of enabling or disabling feature gates.
-->
WindowsGMSA 功能门
默认情况下，API 服务器和 kubelet 上启用了 WindowsGMSA 功能门（要求将 GMSA 凭据规范从 pod 规范传递到容器运行状态）。有关启用或禁用功能门的说明，请参见 Feature Gates 导览。
<!--
Install the GMSACredentialSpec CRD
A CustomResourceDefinition(CRD) for GMSA credential spec resources needs to be configured on the cluster to define the custom resource type GMSACredentialSpec. Download the GMSA CRD YAML and save it as gmsa-crd.yaml. Next, install the CRD with kubectl apply -f gmsa-crd.yaml
-->
安装 GMSACredentialSpec CRD
需要在集群上配置GMSA凭据规范资源的 CustomResourceDefinition（CRD），从而定义自定义资源类型 GMSACredentialSpec。下载 GMSA CRD YAML 并将其保存为 GMSA-crd.yaml。接下来，用命令 kubectl apply-f gmsa 安装 CRD-crd.yaml。
<!--
Install webhooks to validate GMSA users
Two webhooks need to be configured on the Kubernetes cluster to populate and validate GMSA credential spec references at the Pod or container level:
1.A mutating webhook that expands references to GMSAs (by name from a Pod specification) into the full credential spec in JSON form within the Pod spec.
2.A validating webhook ensures all references to GMSAs are authorized to be used by the Pod service account.
-->
安装 webhooks 验证 GMSA 用户
需要在 Kubernetes 集群上配置两个 webhooks 才能在 pod 或容器级别上转换和验证 GMSA 凭证规范参考材料：
1.用于转换的 webhook 可以把 GMSA 的引用（按照 pod 规范中的名称）扩展为 Pod 规范中符合JSON 形式的完整凭据规范。
2.用于验证的 webhook 可以确保 Pod 服务帐户有权使用所有 GMSA 的材料。
<!--
Installing the above webhooks and associated objects require the steps below:
1.Create a certificate key pair (that will be used to allow the webhook container to communicate to the cluster)
2.Install a secret with the certificate from above.
3.Create a deployment for the core webhook logic.
4.Create the validating and mutating webhook configurations referring to the deployment.
-->
安装上述 webhook 和相关对象需要以下步骤：
1.创建证书密钥对（将用于允许 webhook 容器与集群通信）
2.用上面的证书安装密钥。
3.为核心 webhook 逻辑系统创建deployment。
4.根据deployment创建验证和转换 webhook 配置。
<!--
A script can be used to deploy and configure the GMSA webhooks and associated objects mentioned above. The script can be run with a --dry-run option to allow you to review the changes that would be made to your cluster.
-->
script 可用于部署和配置上述 GMSA webhooks 和相关对象。该脚本可以使用--dry-run选项运行，以便查看对集群做出的更改。
<!--
The YAML template used by the script may also be used to deploy the webhooks and associated objects manually (with appropriate substitutions for the parameters)
-->
脚本中使用的YAML template也可以用于手动部署 webhook 和相关对象（对参数进行适当的替换）
{{% /capture %}}
{{% capture steps %}}
<!--
Configure GMSAs and Windows nodes in Active Directory
Before Pods in Kubernetes can be configured to use GMSAs, the desired GMSAs need to be provisioned in Active Direc、tory as described in the Windows GMSA documentation. Windows worker nodes (that are part of the Kubernetes cluster) need to be configured in Active Directory to access the secret credentials associated with the desired GMSA as described in the Windows GMSA documentation
-->
在 Active Directory 中配置 GMSA 和 Windows 节点
在为使用 GMSA 对 Kubernetes 中的 pod 进行配置之前，需要按照 Windows GMSA documentation 的描述在 Active Directory 中配置所需的 GMSA。要访问与所需 GMSA 相关联的加密凭据，需按照 Windows GMSA documentation 中描述的，在 Active Directory 中配置 Windows worker 节点（Kubernetes 集群的一部分）
<!--
Create GMSA credential spec resources
With the GMSACredentialSpec CRD installed (as described earlier), custom resources containing GMSA credential specs can be configured. The GMSA credential spec does not contain secret or sensitive data. It is information that a container runtime can use to describe the desired GMSA of a container to Windows. GMSA credential specs can be generated in YAML format with a utility PowerShell script.
-->
创建 GMSA 凭证规范资源
安装了 GMSACredentialSpec CRD （如前所述）后，就可以配置包含 GMSA凭据规范的自定义资源。 GMSA 凭证规范不能包含机密或敏感数据。容器在运行状态可以使用该信息来向 Windows 描述容器需要的 GMSA。可以使用实用程序 PowerShell script 生成 YAML 格式的 GMSA 凭据规范。
<!--
Following are the steps for generating a GMSA credential spec YAML manually in JSON format and then converting it:
1.Import the CredentialSpec module: ipmo CredentialSpec.psm1
2.Create a credential spec in JSON format using New-CredentialSpec. To create a GMSA credential spec named WebApp1, invoke New-CredentialSpec -Name WebApp1 -AccountName WebApp1 -Domain $(Get-ADDomain -Current LocalComputer)
3.Use Get-CredentialSpec to show the path of the JSON file.
4.Convert the credspec file from JSON to YAML format and apply the necessary header fields apiVersion, kind, metadata and credspec to make it a GMSACredentialSpec custom resource that can be configured in Kubernetes.
-->
以下步骤是手动生成并转换 JSON 格式的 GMSA 凭证规范 YAML ：
1.导入 CredentialSpec module: ipmo CredentialSpec.psm1
2.使用 New-CredentialSpec 创建 JSON 格式的凭证规范。创建名为 WebApp1 的 GMSA 凭证规范，请调用 New-CredentialSpec -Name WebApp1 -AccountName WebApp1 -Domain $(Get-ADDomain -Current LocalComputer)
3.使用 Get-CredentialSpec 显示 JSON 文件的路径。
4.将 credspec 文件从 JSON 格式转换为 YAML 格式，在 Kubernetes中应用必要的头文件字段 apiVersion, kind, metadata 和 credspec 配置 GMSACredentialSpec 自定义资源。
<!--
The following YAML configuration describes a GMSA credential spec named gmsa-WebApp1:
-->
下述的YAML 配置介绍了名为 gmsa-WebApp1 的GMSA凭证规范：
apiVersion: windows.k8s.io/v1alpha1
kind: GMSACredentialSpec
metadata:
  name: gmsa-WebApp1  #This is an arbitrary name but it will be used as a reference
credspec:
  ActiveDirectoryConfig:
    GroupManagedServiceAccounts:
    - Name: WebApp1   #Username of the GMSA account
      Scope: CONTOSO  #NETBIOS Domain Name
    - Name: WebApp1   #Username of the GMSA account
      Scope: contoso.com #DNS Domain Name
  CmsPlugins:
  - ActiveDirectory
  DomainJoinConfig:
    DnsName: contoso.com  #DNS Domain Name
    DnsTreeName: contoso.com #DNS Domain Name Root
    Guid: 244818ae-87ac-4fcd-92ec-e79e5252348a  #GUID
    MachineAccountName: WebApp1 #Username of the GMSA account
    NetBiosName: CONTOSO  #NETBIOS Domain Name
    Sid: S-1-5-21-2126449477-2524075714-3094792973 #SID of GMSA
<!--
The above credential spec resource may be saved as gmsa-Webapp1-credspec.yaml and applied to the cluster using: kubectl apply -f gmsa-Webapp1-credspec.yml
-->
上述凭证规范资源可以另存为 gmsa-Webapp1-credspec.yaml，并使用以下命令应用于集群：kubectl apply -f gmsa-Webapp1-credspec.yml
<!--
Configure cluster role to enable RBAC on specific GMSA credential specs
A cluster role needs to be defined for each GMSA credential spec resource. This authorizes the use verb on a specific GMSA resource by a subject which is typically a service account. The following example shows a cluster role that authorizes usage of the gmsa-WebApp1 credential spec from above. Save the file as gmsa-webapp1-role.yaml and apply using kubectl apply -f gmsa-webapp1-role.yaml
-->
配置集群角色以便在特定 GMSA 凭据规范上启用 RBAC 
需要为每个 GMSA 凭证规范资源定义集群角色。这一步可以通过对象（通常是服务帐户）授权角色在特定 GMSA 资源上进行操作。以下示例表示一个集群角色，该角色获得了 gmsa-WebApp1 凭据规范的使用授权。将文件另存为 gmsa-webapp1-role.yaml 并使用 kubectl apply -f gmsa-webapp1-role.yaml 应用文件。
#Create the Role to read the credspec
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: webapp1-role
rules:
- apiGroups: ["windows.k8s.io"]
  resources: ["gmsacredentialspecs"]
  verbs: ["use"]
  resourceNames: ["gmsa-WebApp1"]
<!--
Assign role to service accounts to use specific GMSA credspecs
A service account (that Pods will be configured with) needs to be bound to the cluster role create above. This authorizes the service account to use the desired GMSA credential spec resource. The following shows the default service account being bound to a cluster role webapp1-role to use gmsa-WebApp1 credential spec resource created above.
-->
为服务账户分配角色以便使用特定的 GSMA 信用规范
首先将一个服务帐户（用于配置 Pod 的服务帐户）绑定到上面创建的集群角色。这一步授权服务帐户可以使用所需的GMSA凭证规范资源。下面示例表示将默认服务帐户绑定到集群角色 webapp1-role 上，可以使用上面创建的 gmsa-WebApp1 凭据规范资源。
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: allow-default-svc-account-read-on-gmsa-WebApp1
  namespace: default
subjects:
- kind: ServiceAccount
  name: default
  namespace: default
roleRef:
  kind: ClusterRole
  name: webapp1-role
  apiGroup: rbac.authorization.k8s.io
<!--
Configure GMSA credential spec reference in Pod spec
The Pod spec field securityContext.windowsOptions.gmsaCredentialSpecName is used to specify references to desired GMSA credential spec custom resources in Pod specs. This configures all containers in the Pod spec to use the specified GMSA. A sample Pod spec with the annotation populated to refer to gmsa-WebApp1:
-->
在 Pod 规范中配置 GMSA 凭据规范资源
Pod 规范字段 securityContext.windowsOptions.gmsaCredentialSpecName 用于在 Pod 规范中指定对所需 GMSA 凭据规范自定义资源的引用。这一步明确 Pod 规范中的所有容器使用指定的 GMSA。以下是有注释的 Pod 规范样本附加到上面提到的 gmsa-WebApp1：
apiVersion: apps/v1beta1
kind: Deployment
metadata:
  labels:
    run: with-creds
  name: with-creds
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      run: with-creds
  template:
    metadata:
      labels:
        run: with-creds
    spec:
      securityContext:
        windowsOptions:
          gmsaCredentialSpecName: gmsa-webapp1
      containers:
      - image: mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2019
        imagePullPolicy: Always
        name: iis
      nodeSelector:
        beta.kubernetes.io/os: windows
<!--
Individual containers in a Pod spec can also specify the desired GMSA credspec using a per-container securityContext.windowsOptions.gmsaCredentialSpecName field. For example:
-->
Pod 规范中的各个容器还可以使用每个容器的securityContext.windowsOptions.gmsaCredentialSpecName 字段指定所需的 GMSA credspec。例如：
apiVersion: apps/v1beta1
kind: Deployment
metadata:
  labels:
    run: with-creds
  name: with-creds
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      run: with-creds
  template:
    metadata:
      labels:
        run: with-creds
    spec:
      containers:
      - image: mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2019
        imagePullPolicy: Always
        name: iis
        securityContext:
          windowsOptions:
            gmsaCredentialSpecName: gmsa-Webapp1
      nodeSelector:
        beta.kubernetes.io/os: windows
<!--
As Pod specs with GMSA fields populated (as described above) are applied in a cluster, the following sequence of events take place:
-->
当填充了 GMSA 字段（如上所述）的 Pod 规范应用于集群中时，将发生以下事件：
<!--
1.The mutating webhook resolves and expands all references to GMSA credential spec resources to the contents of the GMSA credential spec.
2.The validating webhook ensures the service account associated with the Pod is authorized for the use verb on the specified GMSA credential spec.
3.The container runtime configures each Windows container with the specified GMSA credential spec so that the container can assume the identity of the GMSA in Active Directory and access services in the domain using that identity.
-->
1.根据 GMSA 凭证规范的内容，用于转换的 webhook 解析并扩展所有对 GMSA 凭证规范资源的引用。
2.用于验证的 webhook 确保与 Pod 关联的服务帐户可以获得授权进行指定 GMSA 凭证规范上的操作。
3.容器运行状态下使用指定的 GMSA 凭据规范配置每个 Windows 容器，以便容器可以在 Active Directory 中设定 GMSA 的标识，并使用该标识访问域中的服务。
<!--
Troubleshooting
If you are having difficulties getting GMSA to work in your environment, there are a few troubleshooting steps you can take.
-->
故障排除
如果您的环境在配置 GMSA 时遇到问题，可以采取这些步骤排除故障。
<!--
First, make sure the credspec has been passed to the Pod. To do this you will need to exec into one of your Pods and check the output of the nltest.exe /parentdomain command. In the example below the Pod did not get the credspec correctly:
-->
首先，确保 credspec 已经传递到 Pod。为此，您需要进入一个 Pod，并检查命令 nltest.exe / parentdomain 的输出。在下面的示例中，Pod 没有正确获取 credspec：
kubectl exec -it iis-auth-7776966999-n5nzr powershell.exe

Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\> nltest.exe /parentdomain
Getting parent domain failed: Status = 1722 0x6ba RPC_S_SERVER_UNAVAILABLE
PS C:\>
<!--
If your Pod did get the credspec correctly, then next check communication with the domain. First, from inside of your Pod, quickly do an nslookup to find the root of your domain.
-->
如果您的 Pod 正确获取了 credspec，接下来检查与域的通信。首先，在您的Pod 内部运行 nslookup 来快速查找域的根。
<!--
This will tell us 3 things:
1.The Pod can reach the DC
2.The DC can reach the Pod
3.DNS is working correctly.
-->
这代表三点:
1.Pod 可以触达 DC
2.DC 也可以触达 Pod
3.DNS 正在正常工作
<!--
If the DNS and communication test passes, next you will need to check if the Pod has established secure channel communication with the domain. To do this, again, exec into your Pod and run the nltest.exe /query command.
-->
如果 DNS 和通信测试通过，接下来您需要检查 Pod 是否与域建立了安全信道通信。为此，再次进入Pod中并运行命令 nltest.exe / query。
PS C:\> nltest.exe /query
I_NetLogonControl failed: Status = 1722 0x6ba RPC_S_SERVER_UNAVAILABLE
<!--
This tells us that for some reason, the Pod was unable to logon to the domain using the account specified in the credspec. You can try to repair the secure channel by running the nltest.exe /sc_reset:domain.example command.
-->
这说明由于某种原因，Pod 无法使用 credspec 中指定的帐户登录域。您可以尝试通过运行命令 nltest.exe /sc_reset:domain.example 来修复安全信道。
PS C:\> nltest /sc_reset:domain.example
Flags: 30 HAS_IP  HAS_TIMESERV
Trusted DC Name \\dc10.domain.example
Trusted DC Connection Status Status = 0 0x0 NERR_Success
The command completed successfully
PS C:\>
<!--
If the above command corrects the error, you can automate the step by adding the following lifecycle hook to your Pod spec. If it did not correct the error, you will need to examine your credspec again and confirm that it is correct and complete.
-->
如果以上命令纠正了错误，那么可以将以下 lifecycle hook 添加到 Pod 规范中，从而自动执行该步骤。如果以上命令不能纠正错误，那么需要再次检查 credspec 并确认它是否正确无误。
        image: registry.domain.example/iis-auth:1809v1
        lifecycle:
          postStart:
            exec:
              command: ["powershell.exe","-command","do { Restart-Service -Name netlogon } while ( $($Result = (nltest.exe /query); if ($Result -like '*0x0 NERR_Success*') {return $true} else {return $false}) -eq $false)"]
        imagePullPolicy: IfNotPresent
<!--
If you add the lifecycle section show above to your Pod spec, the Pod will execute the commands listed to restart the netlogon service until the nltest.exe /query command exits without error.
-->
如果将上面显示的 lifecycle 部分添加到 Pod 规范中，Pod 将执行这些命令来重新启动 netlogon 服务，直到命令 nltest.exe / query 正确才会退出。
{{% /capture %}}
