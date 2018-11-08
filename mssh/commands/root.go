package commands

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

type flags struct {
	hosts      bool
	hostsf     string
	user       string
	password   string
	passwordf  bool
	privateKey string
	command    string
	port       string
}

type output struct {
	stdout bytes.Buffer
	stderr bytes.Buffer
	host   string
}

var config flags
var usr, _ = user.Current()

var RootCmd = &cobra.Command{
	Use:  "mssh [command]",
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		mainProc(args)
	},
}

func init() {
	RootCmd.Flags().StringVarP(&config.hostsf, "hosts-file", "f", "", "Will take a list of servers from file")
	RootCmd.Flags().BoolVarP(&config.hosts, "hosts", "H", false, "Will take a list of servers from stdin")
	RootCmd.Flags().StringVarP(&config.user, "user", "u", usr.Username, "Specify different user")
	RootCmd.Flags().StringVarP(&config.password, "password", "p", "", "Specify password to use via command line")
	RootCmd.Flags().BoolVarP(&config.passwordf, "password_prompt", "P", false, "Will ask to enter password from prompt")
	RootCmd.Flags().StringVarP(&config.privateKey, "private_key", "i", usr.HomeDir+"/.ssh/id_rsa", "Specify full path to private key")
	RootCmd.Flags().StringVarP(&config.port, "port", "", "22", "Port to be used to connect")
}

func getHostList() []string {
	var hosts []string
	if config.hosts == true {
		fmt.Println("Please enter a list of server names(to stop, enter \".\"):")
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			if scanner.Text() == "." {
				break
			}
			hosts = append(hosts, scanner.Text())
		}
		return hosts

	} else if config.hostsf != "" {
		contents, err := ioutil.ReadFile(config.hostsf)
		if err != nil {
			log.Fatalf("Error reading file: %s, %s", config.hostsf, err)
		}
		for _, h := range strings.Split(string(contents[:]), "\n") {
			if h != "" {
				hosts = append(hosts, h)
			}
		}
		return hosts

	} else {
		log.Fatal("-h (--hosts-file) or -H (--hosts) flags are required to input host list")
	}
	return hosts
}

func getAuthMethods() ([]ssh.AuthMethod, error) {
	var authMethods []ssh.AuthMethod
	if config.passwordf == true {
		fmt.Print("Password:")
		passwd, _ := terminal.ReadPassword(0)
		fmt.Println()
		authMethods = append(authMethods, ssh.Password(string(passwd)))
	} else if config.password != "" {
		authMethods = append(authMethods, ssh.Password(string(config.password)))
	}

	keyfile, err := ioutil.ReadFile(config.privateKey)
	if err != nil {
		log.Printf("Could not open private key file: %s", config.privateKey)
	} else {
		signer, err := ssh.ParsePrivateKey(keyfile)
		if err != nil {
			log.Printf("Could not parse private key: %s, error: %s", config.privateKey, err)
		} else {
			authMethods = append(authMethods, ssh.PublicKeys(signer))
		}
	}
	if len(authMethods) == 0 {
		return authMethods, fmt.Errorf("There were errors while generating a list of possible authentication methods")
	} else {
		return authMethods, nil
	}
}

func getSSHConfig(user string, auths []ssh.AuthMethod) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            user,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
}

func runSSHCommand(ch chan<- output, wg *sync.WaitGroup, host string, port string, command string, config *ssh.ClientConfig) {
	fmt.Printf("Connecting to: %s\n", host)
	defer wg.Done()
	std := output{}
	std.host = host
	connStr := fmt.Sprintf("%s:%s", host, port)
	client, err := ssh.Dial("tcp", connStr, config)
	if err != nil {
		fmt.Println(err)
		return
	}

	session, err := client.NewSession()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer session.Close()

	session.Stdout = &std.stdout
	session.Stderr = &std.stderr

	if err := session.Run(command); err != nil {
		fmt.Println(err)
	}
	ch <- std
}

func mainProc(args []string) {
	command := args[0]
	hosts := getHostList()
	auths, err := getAuthMethods()
	if err != nil {
		log.Fatalf("%v", err)
	}
	sshConfig := getSSHConfig(config.user, auths)

	var wg sync.WaitGroup
	ch := make(chan output)
	for _, host := range hosts {
		wg.Add(1)
		go runSSHCommand(ch, &wg, host, config.port, command, sshConfig)
	}
	fmt.Println("Output:")
	go func() {
		for a := range ch {
			fmt.Println(a.host)
			fmt.Println(strings.Trim(a.stdout.String(), "\n"))
			fmt.Println("**************************")
		}
	}()
	wg.Wait()
	close(ch)
}
