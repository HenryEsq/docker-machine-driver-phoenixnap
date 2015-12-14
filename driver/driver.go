package driver

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"strings"

	pncp "github.com/allingeek/pncp-sdk-go"
	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/ssh"
	"github.com/docker/machine/libmachine/state"
	gssh "golang.org/x/crypto/ssh"
	//"github.com/docker/machine/libmachine/mcnutils"
)

type Driver struct {
	*drivers.BaseDriver
	Endpoint       string
	AccountID      string
	ApplicationKey string
	SharedSecret   string
	NodeID         string

	OSTemplate  string
	MemoryInMB  uint32
	StorageInGB uint16
	VCpuCount   uint8
	StorageType string

	VMResourceURL string

	//	AccessToken       string
	//	DropletID         int
	//	DropletName       string
	//	Image             string
	//	Region            string
	//	SSHKeyID          int
	//	Size              string
	//	IPv6              bool
	//	Backups           bool
	//	PrivateNetworking bool
}

const (
	drivername         = "phoenixnap"
	defaultEndpoint    = "https://admin.phoenixnap.com/pncp-external-api-rest/"
	defaultNode        = ""
	defaultOSTemplate  = "/ostemplate/64" // Looked this up from the live site
	defaultMemoryInMB  = 1000
	defaultStorageInGB = 16
	defaultVCpuCount   = 1
	defaultStorageType = "SATA"
	temporaryPassword  = `thisisapcnpmachinedefaultpassword`
)

func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			EnvVar: "PHXNAP_ENDPOINT",
			Name:   "phoenixnap-endpoint",
			Usage:  "PhoenixNAP node endpoint.",
			Value:  defaultEndpoint,
		},
		mcnflag.StringFlag{
			EnvVar: "PHXNAP_ACCOUNT_ID",
			Name:   "phoenixnap-account-id",
			Usage:  "Your PhoenixNAP account ID.",
		},
		mcnflag.StringFlag{
			EnvVar: "PHXNAP_APPLICATION_KEY",
			Name:   "phoenixnap-application-key",
			Usage:  "Your PhoenixNAP account application key.",
		},
		mcnflag.StringFlag{
			EnvVar: "PHXNAP_SHARED_SECRET",
			Name:   "phoenixnap-shared-secret",
			Usage:  "Your PhoenixNAP shared secret.",
		},
		mcnflag.StringFlag{
			EnvVar: "PHXNAP_NODE_ID",
			Name:   "phoenixnap-node-id",
			Usage:  "The PhoenixNAP node ID.",
			Value:  defaultNode,
		},
		//mcnflag.StringFlag{
		//	EnvVar: "PHXNAP_OS_TEMPLATE",
		//	Name:   "phoenixnap-os-template",
		//	Usage:  "The operating system template that Docker will be installed on.",
		//	Value:  defaultOSTemplate,
		//},
	}
}

func NewDriver(hostName, storePath string) *Driver {
	return &Driver{
		BaseDriver: &drivers.BaseDriver{
			MachineName: hostName,
			StorePath:   storePath,
		},
		OSTemplate:  defaultOSTemplate,
		Endpoint:    defaultEndpoint,
		MemoryInMB:  defaultMemoryInMB,
		StorageInGB: defaultStorageInGB,
		VCpuCount:   defaultVCpuCount,
		StorageType: defaultStorageType,
	}
}

func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	d.SwarmMaster = flags.Bool("swarm-master")
	d.SwarmHost = flags.String("swarm-host")
	d.SwarmDiscovery = flags.String("swarm-discovery")

	d.Endpoint = flags.String("phoenixnap-endpoint")
	d.AccountID = flags.String("phoenixnap-account-id")
	d.ApplicationKey = flags.String("phoenixnap-application-key")
	d.SharedSecret = flags.String("phoenixnap-shared-secret")
	d.NodeID = flags.String("phoenixnap-node-id")
	//d.OSTemplate = flags.String("phoenixnap-os-template")

	d.SSHPort = 22
	d.SSHUser = `root`

	return nil
}

// This driver uses the SDk provided by phoenixnap.API
func (d *Driver) getClient() pncp.API {
	return pncp.NewClient(d.Endpoint, d.AccountID, d.ApplicationKey, d.SharedSecret, d.NodeID, true)
}

func (d *Driver) DriverName() string {
	return drivername
}

func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()
}

func (d *Driver) GetURL() (string, error) {
	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("tcp://%s", net.JoinHostPort(ip, "2376")), nil
}

func (d *Driver) PreCreateCheck() error {
	// pickup the phoenixnap client and validate the driver configuration
	client := d.getClient()
	f, err := client.GetAccountDetails()
	if err != nil {
		return err
	}

	details := &pncp.AccountDetails{}
	err = f.Get(details)
	if err != nil {
		log.Warn(`Unable to unmarshall response.`)
		return err
	}

	log.Debug(fmt.Sprintf(`Account Details: %s`, details))

	if details.AccountStatus != pncp.AccountStatusGoodStanding {
		log.Warn(`Account not in good standing with PhoenixNAP. ` + fmt.Sprintf("Reported Status: %s", details.AccountStatus))
	}

	return nil
}

func (d *Driver) Create() error {
	log.Info("Creating new machine...")
	client := d.getClient()

	req := pncp.CreateVMRequest{
		Name:                    d.MachineName,
		Description:             `This is a test machine for Docker Machine integration.`,
		StorageInGB:             16,
		MemoryInMB:              4096,
		VCpuCount:               1,
		StorageType:             `SATA`,       // docs report optional, but service 500s if excluded
		PowerStatus:             `POWERED_ON`, // docs report optional, but service 500s if excluded
		OperatingSystemTemplate: pncp.Resource{URL: `/ostemplate/59`},
		Password:                temporaryPassword,
	}
	cvmf, err := client.CreateVirtualMachine(req)
	if err != nil {
		return err
	}

	res := &pncp.Resource{}
	err = cvmf.Get(res)
	if err != nil {
		return err
	}
	d.VMResourceURL = res.URL
	if d.VMResourceURL == "" {
		return errors.New(`VM Resource URL unspecified by PNCP.`)
	}

	log.Debugf("VM Resource URL: %s", d.VMResourceURL)

	ipf, err := client.AssignPublicIPToVirtualMachineResource(d.VMResourceURL, pncp.PublicIPSpec{})
	if err != nil {
		return err
	}
	err = ipf.Get(&pncp.Resource{})
	if err != nil {
		return err
	}

	rebf, err := client.RebootVirtualMachineResource(d.VMResourceURL)
	if err != nil {
		return err
	}
	res = &pncp.Resource{}
	err = rebf.Get(res)
	if err != nil {
		return err
	}

	iplf, err := client.ListPublicIPsForVirtualMachineResource(d.VMResourceURL)
	if err != nil {
		return err
	}
	ips := []pncp.Resource{}
	err = iplf.Get(&ips)
	if err != nil {
		return err
	}
	log.Debugf("Public IPs: %s", ips)
	if len(ips) == 0 {
		return errors.New("No IP address assigned for VM.")
	}

	ipdf, err := client.GetPublicIPResourceDetails(ips[0].URL)
	if err != nil {
		return err
	}
	ipDetail := &pncp.PublicIPAssignmentDesc{}
	err = ipdf.Get(ipDetail)
	if err != nil {
		return err
	}
	log.Debugf("IP Assignment Details: %s", ipDetail)
	d.IPAddress = ipDetail.IPAddress

	if err = installSSHKey(d.GetSSHKeyPath(), d.SSHUser, temporaryPassword, d.IPAddress, d.SSHPort); err != nil {
		return err
	}

	return nil
}

func installSSHKey(keyPath string, user string, password string, host string, port int) error {
	if err := ssh.GenerateSSHKey(keyPath); err != nil {
		return err
	}
	publicKey, err := ioutil.ReadFile(keyPath + ".pub")
	if err != nil {
		return err
	}

	// unset HISTFILE;
	// passwd << somethingrandom
	log.Debug(fmt.Sprintf("mkdir -p ~/.ssh; echo '%s' >> ~/.ssh/authorized_keys", strings.TrimSpace(string(publicKey))))
	cmd := fmt.Sprint(`echo Hello World`)
	log.Debug(cmd)

	auth := ssh.Auth{Passwords: []string{password}}
	log.Debug(auth)
	sshConfig, err := ssh.NewNativeConfig(user, &auth)
	if err != nil {
		return err
	}
	log.Debug(sshConfig)

	sshCall(host)
	/*
		if err := mcnutils.WaitFor(func() bool {
			if _, err := gssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), &sshConfig); err != nil {
				log.Debugf("Errrrrrrror dialing TCP: %s", err)
				return false
			}
			return true
		}); err != nil {
			return fmt.Errorf("Error attempting SSH client dial: %s", err)
		}
		conn, err := gssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), &sshConfig)
		if err != nil {
			return fmt.Errorf("Mysterious error dialing TCP for SSH (we already succeeded at least once) : %s", err)
		}
		session, err := conn.NewSession()
		if err != nil {
			return fmt.Errorf("Unable to establish a new session: %s", err)
		}
		defer session.Close()

		if err := session.Run(cmd); err != nil {
			panic("Failed to run: " + err.Error())
		}
	*/
	return nil

	/*

		client, err := ssh.NewNativeClient(user, host, port, &auth)
		if err != nil {
			return err
		}

		// This need for specialization is RedHat specific

		switch c := client.(type) {
		case ssh.ExternalClient:
			log.Debugf("Binary path: %s", c.BinaryPath)
			log.Debugf("Base arguments: %s", c.BaseArgs)
			//c.BaseArgs = append(c.BaseArgs, "-tt")
			//client = c
		case ssh.NativeClient:
			//o, e := c.OutputWithPty(cmd)
			//log.Debug(o)
			//return e
		}
		return client.Shell(cmd)
	*/
}

func sshCall(host string) {
	var (
		config  *gssh.ClientConfig
		client  *gssh.Client
		session *gssh.Session
		err     error

		b bytes.Buffer
	)
	config = &gssh.ClientConfig{
		User: "root",
		Auth: []gssh.AuthMethod{gssh.Password(temporaryPassword)},
	}

	target := net.TCPAddr{
		IP:   net.ParseIP(host),
		Port: 22,
	}
	if client, err = gssh.Dial("tcp", target.String(), config); err != nil {
		panic("Failed to dial: " + err.Error())
	}
	if session, err = client.NewSession(); err != nil {
		panic("Failed to create session: " + err.Error())
	}
	defer session.Close()

	session.Stdout = &b
	if err = session.Run("/usr/bin/whoami"); err != nil {
		panic("Failed to run: " + err.Error())
	}
	fmt.Println(b.String())
}

////////// WORKING LINE //////////////

func (d *Driver) GetSSHPort() (int, error) {
	return d.SSHPort, nil
}

func (d *Driver) GetSSHUsername() string {
	return d.SSHUser
}

func (d *Driver) GetState() (state.State, error) {
	log.Debugf("Attempting to pull status for %s", d.VMResourceURL)
	vmd, err := d.getClient().GetVirtualMachineResourceDetails(d.VMResourceURL)
	if err != nil {
		return state.Error, err
	}
	deets := &pncp.VirtualMachineDetails{}
	err = vmd.Get(deets)
	if err != nil {
		return state.Error, err
	}
	log.Debug(deets)

	return state.Running, nil
}

func (d *Driver) Kill() error {
	return fmt.Errorf("hosts without a driver cannot be killed")
}

func (d *Driver) Remove() error {
	client := d.getClient()

	var (
		url string      // the virtual machine resource URL
		pf  pncp.Future // the powerdown future
		rmf pncp.Future // the removal future
		res *pncp.Resource
		err error
	)

	if d.VMResourceURL != "" {
		log.Debugf("Powering down resource: %s", d.VMResourceURL)
		url = d.VMResourceURL
	} else {
		log.Debugf("Powering down machine: %s", d.MachineName)
		vmlist, err := getVMList(client)
		if err != nil { return err }
		r, err := filterResourcesForMachineName(client, vmlist, d.MachineName)
		if err != nil { return err }
		log.Debugf("Resolved machine resource URL to: %s", r.URL)
		url = r.URL
	}

	// Shutdown the box - If error just try to delete
	pf, err = client.SetVirtualMachineResourcePowerState(url, `off`)
	res = &pncp.Resource{}
	err = pf.Get(res)
	if err != nil {
		fmt.Errorf("%s", err)
	}

	// Delete the virtual machine and release the IP
	rmf, err = client.DeleteVirtualMachineResource(url, true)
	if err != nil {
		return err
	}
	res = &pncp.Resource{}
	err = rmf.Get(res)
	if err != nil {
		return err
	}
	return nil
}

func (d *Driver) Restart() error {
	return fmt.Errorf("hosts without a driver cannot be restarted")
}

func (d *Driver) Start() error {
	return nil
}

func (d *Driver) Stop() error {
	return nil
}

// Utility functions
func getVMList(c pncp.API) (pncp.ResourceList, error) {
	if c == nil {
		return nil, errors.New(`The client must be non-nil`)
	}

	lf, err := c.ListVirtualMachinesByAccount()
	if err != nil {
		return nil, err
	}
	list := &pncp.ResourceList{}
	err = lf.Get(list)
	if err != nil {
		return nil, err
	}
	return *list, nil
}

func filterResourcesForMachineName(c pncp.API, list pncp.ResourceList, name string) (*pncp.Resource, error) {
	log.Debugf("Filtering VM resource list for: %s", name)
	for _, key := range list {
		vmd, err := c.GetVirtualMachineResourceDetails(key.URL)
		if err != nil {
			return nil, err
		}
		d := &pncp.VirtualMachineDetails{}
		err = vmd.Get(d)
		if err != nil {
			return nil, err
		}
		log.Debugf("Pulled details for: %s, %s", key.URL, d)
		if d.Name == name {
			log.Debugf(`Found: %s`, name)
			return &key, nil
		}
	}
	return nil, errors.New(fmt.Sprintf(`No machine with name %s found among the provided resource list.`, name))
}
