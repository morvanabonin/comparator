package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type (
	QuestionDNS struct {
		Name   string `json:"Name"`
		Qtype  uint16 `json:"Qtype"`
		Qclass uint16 `json:"Qclass"`
	}
)

// Dados já do teste real
// prod
//const (
//	IpAddress1 = "172.30.1.242" // IP do atual DNS
//	Port1      = ":53"
//	IpAddress2 = "127.0.0.1" // IP do serviço que ficará o novo DNS
//	Port2      = ":53"
//	ChannelQtd = 100
//)

// testes
const  (
	IpAddress1  = "192.168.101.117" // "172.30.1.242" IP do atual DNS
	Port1       = ":53"
	IpAddress2  = "192.168.101.117" // IP do serviço que ficará o novo DNS
	Port2       = ":1553"
	ChannelQtd  = 1
)

var (
	IgnoreDomains = []string{
		"x99moyu.net",
		"duobao369.com",
		"mktwalmart.com.br",
		"mktnacional.com.br",
		"mktsuperbompreco.com.br",
		"mktmercadorama.com.br",
		"mkttododia.com.br",
		"mktbig.com.br",
		"mktmaxxi.com.br",
		"mktbigbompreco.com.br",
		"mta-sts.mail.", // Chuva de requisições
	}

	executeExchange chan QuestionDNS
	catchError string
	catchError2 string
	waitCompare sync.WaitGroup
)

// Esse script foi criado para comparar as respostas de uma query/questão de DNS
// o retorno é para saber qual dessas queries/questões precisam ser trabalhadas,
// caso o retorno não seja okay
func main() {
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			fmt.Println("Recuperado de ", r)
			fmt.Println("Stack ", string(stack))
			return
		}
	}()

	// criação do channel
	executeExchange = make(chan QuestionDNS)

	// chamado em uma goroutine do compare passando para o for a quantidade de vias

	for i := 1; i <= ChannelQtd; i++ {
		go compare()
	}

	// prod
	// pathFile := "/var/log/dinamize/questions-dns/Questions-DNS.json"

	// testes
	pathFile := "/var/log/dinamize/dev/morvana.bonin/dns-questions/Questions-DNS.json"

	path := strings.TrimSpace(filepath.Clean(pathFile))

	f, err := os.Open(path)

	if err != nil {
		log.Panic("Houve erro ao abrir o arquivo ", err.Error())
	}

	defer f.Close()

	// cria e retorna um novo Leitor (Reader) cuja o buffer tem um tamanho default
	reader := bufio.NewReader(f)

	// critério de parada, EOL
	lineNumber := 0
	for {
		var line []byte
		var isPrefix bool

		// É utilizada a função ReadLine para leitura de cada linha do arquivo e retornar em byte
		// https://pkg.go.dev/bufio#Reader.ReadLine
		line, isPrefix, err = reader.ReadLine()
		lineNumber++

		if isPrefix {
			log.Println("A linha é muito longa e foi quebrada retornando apenas a primeira parte", isPrefix)
			continue
		}

		if errors.Is(err, io.EOF) {
			break
		}

		// faz Unmarshal passando a estrutura criada
		// QuestionDNS struct {
		//	Name string `json:"Name"`
		//	Qtype uint16 `json:"Qtype"`
		//	Qclass uint16 `json:"Qclass"`
		// }
		dnsQ := QuestionDNS{}
		err = json.Unmarshal(line, &dnsQ)

		if err != nil {
			log.Panic("Houve erro ao dar Unmarshal", err.Error())
		}

		if ignoreDomains(dnsQ.Name) {
			fmt.Printf("-")
			continue
		}

		// se o dnsQ.Name vier nesse padrão 05c49616-idc
		// nos ignoraremos
		if ignoreHexIPDomains(dnsQ) {
			fmt.Printf("-")
			continue
		}

		// o channel recebe a estrutura de DNS - dnsQ
		waitCompare.Add(1)
		executeExchange <- dnsQ
	}
	waitCompare.Wait()
}

// writeAnswerFile escreve no arquivo
func writeAnswerFile(message string) {
	file, err := os.OpenFile("Comparator-DNS-Error.log", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0766)

	if err != nil {
		log.Fatalf("Houve falha ao criar o artquivo: %s", err.Error())
	}

	defer file.Close()
	byt := []byte(message + "\n")

	if _, errWrite := file.Write(byt); errWrite != nil {
		log.Panicf("Houve falha ao escrever no artquivo: %s", errWrite.Error())
	}

}

// compare função que cria as questões DNS e faz o exchange, além de escrever os retornos
func compare() {

	for {
		// channel
		dnsQ := <-executeExchange

		// Ignora perguntas de tipo CNAME, pois as mesmas, não passam de lixo
		// pois CNAME é apenas para respostas
		if dnsQ.Qtype == 5 {
			fmt.Printf("-")
			waitCompare.Done()
			continue
		}

		// Cria a estrutura da mensagem/questão DNS, uma de cada vez
		// de acordo Go https://pkg.go.dev/github.com/miekg/dns#Question
		m := new(dns.Msg)
		m.Id = dns.Id()
		m.RecursionDesired = true
		m.Question = make([]dns.Question, 1)
		m.Question[0] = dns.Question{
			Name:   dnsQ.Name,
			Qtype:  dnsQ.Qtype,
			Qclass: dnsQ.Qclass,
		}

		// envia a pergunta passando o endereço ip e a porta
		clientDNS := new(dns.Client)
		in1, _, errExchange1 := clientDNS.Exchange(m, IpAddress1+Port1)

		// envia a mesma pergunta para outro endereço ip e porta
		client2DNS := new(dns.Client)
		in2, _, errExchange2 := client2DNS.Exchange(m, IpAddress2+Port2)

		// faz o log do erro da 1ª requisição
		if errExchange1 != nil {
			fmt.Printf("x")

			if strings.Contains(errExchange1.Error(), "timeout") && in2 != nil && len(in2.Answer) == 0 {
				// se deu timeout no sistema de DNS hoje existente e o novo respondeu, mas com a resposta no valor zero
				// nós deixamos passar, pois não consideramos como um caso de erro
				waitCompare.Done()
				continue
			}

			if strings.Contains(errExchange1.Error(), "timeout") {
				catchError = "Timeout: " + errExchange1.Error()
			}

			msg := fmt.Sprintf(timeNow()+" Erro ao enviar a questão DNS [%s] tipo %s, para o IP=[%s] com o erro [%s]",
				dnsQ.Name,
				dns.Type(dnsQ.Qtype).String(),
				IpAddress1,
				catchError)
			writeAnswerFile(msg)
			waitCompare.Done()
			continue
		}

		// faz o log do erro da 2ª requisição
		if errExchange2 != nil {
			if strings.Contains(errExchange2.Error(), "timeout") {
				catchError2 = "Timeout: " + errExchange2.Error()
			}

			fmt.Printf("x")

			msg := fmt.Sprintf(timeNow()+" Erro ao enviar a questão DNS [%s] tipo %s, para o IP=[%s] com o erro [%s]",
				dnsQ.Name,
				dns.Type(dnsQ.Qtype).String(),
				IpAddress2,
				catchError2)
			writeAnswerFile(msg)
			waitCompare.Done()
			continue
		}

		// Condição para ignorar quando for perguntas toscas e sem nexo
		if dnsQ.Qtype == 1 && len(in1.Answer) == 2 && len(in2.Answer) == 0 {
			stringAnswer := in1.Answer[0].String()
			stringAnswer += in1.Answer[1].String()
			if strings.Contains(stringAnswer, "18.189.133.24") &&
				strings.Contains(stringAnswer, "3.139.183.150") {
				fmt.Printf("-")
				waitCompare.Done()
				continue
			}

		}

		// Compara se o slice do response são de tamanhos iguais
		// caso não seja grava em um arquivo as respostas para consulta
		if len(in1.Answer) != len(in2.Answer) {
			fmt.Printf("!")

			// gravar em um file as queries de respostas
			msg := fmt.Sprintf(timeNow()+" Os arrays da questão (%+v) e respostas [%+v] e [%+v] são de tamanhos diferentes.", m.Question, in1.Answer, in2.Answer)
			writeAnswerFile(msg)
			waitCompare.Done()
			continue
		}

		// Gambeta para quando as respostas forem iguais a este caso
		// dns-server01.dinamize.com -> ns1.dnzdns.com
		// dns-server02.dinamize.com -> ns2.dnzdns.com
		if dnsQ.Qtype == 2 && len(in1.Answer) == 2 && len(in2.Answer) == 2 {
			stringAnswer := in1.Answer[0].String()
			stringAnswer += in1.Answer[1].String()
			if strings.Contains(stringAnswer, "dns-server01.dinamize.com") &&
				strings.Contains(stringAnswer, "dns-server02.dinamize.com") {
				fmt.Printf("-")
				waitCompare.Done()
				continue
			}
		}


		// Verifica se os as duas respostas são idênticas
		// caso não seja, grava em arquivo as respostas para consulta
		if !answerExist(in1.Answer, in2.Answer) {

			// Aqui vai a lógica de caso seja diferente as respostas, mas essa for do tipo TXT e v=spf1
			// ordenar os IPs de retorno, ignorando o
			// MX e /32 e
			// comparar os mesmos
			if spfAnswersCompareIps(in1.Answer, in2.Answer) {
				fmt.Printf("=")
				waitCompare.Done()
				continue
			}

			fmt.Printf("!")

			// gravar em um file as queries de respostas
			msg := fmt.Sprintf("As respostas não são idênticas [%+v] e [%+v]", in1.Answer, in2.Answer)
			writeAnswerFile(msg)
			waitCompare.Done()
			continue
		}

		// Verifica se veio Extra no retorno do DNS
		if in1.Extra != nil && in2.Extra != nil {

			if len(in1.Extra) != len(in2.Extra) {

				// se o conjunto da sessão adicional das respostas (conhecido como Extras) de IPs do antigo DNS
				// for menor que do atual DNS então verifica se os valores que vieram no novo estão contido no DNS antigo,
				// se estiver, dar continue
				if len(in1.Extra) < len(in2.Extra) {
					if contains(in1.Extra, in2.Extra) {
						fmt.Printf("=")
						waitCompare.Done()
						continue
					}
				}

				fmt.Printf("!")

				// gravar em um file as queries de respostas
				msg := fmt.Sprintf(timeNow()+" Os arrays da questão (%+v) e Extras [%+v] e [%+v] são de tamanhos diferentes.", m.Question, in1.Extra, in2.Extra)
				writeAnswerFile(msg)
				waitCompare.Done()
				continue
			}

			// Verifica se os as dois Extras são idênticos
			// caso não seja, grava em arquivo as respostas para consulta
			if !answerExist(in1.Extra, in2.Extra) {
				fmt.Printf("!")

				// gravar em um file as queries de respostas
				msg := fmt.Sprintf(timeNow()+" Os Extras não são idênticas [%+v] e [%+v]", in1.Extra, in2.Extra)
				writeAnswerFile(msg)
				waitCompare.Done()
				continue
			}
		}

		// ponto de linha para ver a execução
		fmt.Print("=")

		// sleep 1 segundo
		time.Sleep(100 * time.Millisecond)
		waitCompare.Done()
	}
}

// ignoreDomains ignora domínios da blacklist
func ignoreDomains(q string) bool {
	for _, domain := range IgnoreDomains {
		if strings.Contains(q, domain) {
			return true
		}
	}
	return false
}

// ignoreHexIPDomains ignora a entrada de domínios que inicializam com hexadecimal
func ignoreHexIPDomains(questionDNS QuestionDNS) bool {
	var (
		qname = questionDNS.Name
		qtype = dns.Type(questionDNS.Qtype).String()
	)

	re := regexp.MustCompile(`^[a-f0-9]{8}[^a-z0-9]`)
	if re.MatchString(qname) && qtype == "TXT" {
		return true
	}

	return false
}

// timeNow formata o horário para colocar nos logs
func timeNow() string {
	return time.Now().Format("02-Jan-2006 15:04:05")
}

// answerExist verifica se as respostas são iguais
func answerExist(m, m2 []dns.RR) bool {
	var exist []bool
	var check []bool

	for range m2 {
		check = append(check, false)
	}

	for i, v1 := range m {
		exist = append(exist, false)

		for i2, v2 := range m2 {
			if v1.String() == v2.String() && !check[i2] {
				exist[i] = true
				check[i2] = true
				break
			}
		}
	}

	for _, v := range exist {
		if !v {
			return false
		}
	}

	return true
}

// contains verifica que caso o tamanho das respostas Extras sejam de tamanho diferente,
// no caso o DNS novo ter mais IP, se esses estão contidos no DNS antigo
func contains(ex, ex2 []dns.RR) bool {
	for _, v1 := range ex {
		for _, v2 := range ex2 {
			if strings.Contains(v1.String(), v2.String()) {
				return true
			}
		}
	}
	return false
}

// spfAnswersCompareIps
// Aqui vai a lógica de caso seja diferente as respostas, mas essa for do tipo TXT e v=spf1
// ordenar os IPs de retorno, ignorando o
// MX e /32 e
// comparar os mesmos
func spfAnswersCompareIps(resp1, resp2 []dns.RR) bool {
	var retArrayIps1 []string
	var retArrayIps2 []string

	for _, v1 := range resp1 {
		retArrayIps1 = arrayIps(v1.String())
		for _, v2 := range resp2 {
			retArrayIps2 = arrayIps(v2.String())
			if orderAndCompare(retArrayIps1, retArrayIps2) {
				return true
			}
		}
	}

	return false
}

func arrayIps(v string) []string {
	re := regexp.MustCompile("ip4:.*/[0-9]{2}")
	ipsFound := re.FindString(v)
	r := strings.Split(ipsFound, " ")
	return r
}

func orderAndCompare(ips1, ips2 []string) bool {
	var exist []bool
	var check []bool

	for range ips2 {
		check = append(check, false)
	}

	for i, ip1 := range ips1 {
		exist = append(exist, false)

		if strings.Contains(ip1, "/32") {
			ip1 = strings.TrimRight(ip1, "/32")
		}

		for i2, ip2 := range ips2 {
			if ip1 == ip2 && !check[i2] {
				exist[i] = true
				check[i2] = true
				break
			}
		}
	}

	for _, v := range exist {
		if !v {
			return false
		}
	}

	return true

}
