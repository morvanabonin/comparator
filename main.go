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
const  (
	IpAddress1  = "172.30.1.242" // IP do atual DNS
	Port1       = ":53"
	IpAddress2  = "127.0.0.1" // IP do serviço que ficará o novo DNS
	Port2       = ":53"
)

// testes
//const  (
//	IpAddress1  = "192.168.101.117" //"172.30.1.242" // IP do atual DNS
//	Port1       = ":53"
//	IpAddress2  = "192.168.101.117" // IP do serviço que ficará o novo DNS
//	Port2       = ":53"
//)

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

	// prod
	var pathFile string = "/var/log/dinamize/questions-dns/Questions-DNS.json"

	// testes
	// var pathFile string = "/var/log/dinamize/dev/morvana.bonin/dns-questions/Questions-DNS.json"

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

		// sleep 1 segundo
		time.Sleep(100 * time.Millisecond)

		// É utilizada a função ReadLine para leitura de cada linha do arquivo e retornar em byte
		// https://pkg.go.dev/bufio#Reader.ReadLine
		line, isPrefix, err = reader.ReadLine()
		lineNumber++

		// ponto de linha para ver a execução
		fmt.Print(".")

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
		dnsQ := new(QuestionDNS)
		err = json.Unmarshal(line, dnsQ)

		if err != nil {
			log.Panic("Houve erro ao dar Unmarshal", err.Error())
		}

		if ignoreDomains(dnsQ.Name) {
			continue
		}

		// se o dnsQ.Name vier nesse padrão 05c49616-idc
		// nos ignoraremos
		if ignoreHexIPDomains(dnsQ) {
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
			Qclass: dnsQ.Qclass}

		// envia a pergunta passando o endereço ip e a porta
		clientDNS := new(dns.Client)
		in1, _, errExchange1 := clientDNS.Exchange(m, IpAddress1+Port1)

		// envia a mesma pergunta para outro endereço ip e porta
		client2DNS := new(dns.Client)
		in2, _, errExchange2 := client2DNS.Exchange(m, IpAddress2+Port2)

		// faz o log do erro da 1ª requisição
		if errExchange1 != nil {
			if strings.Contains(errExchange1.Error(), "timeout") && in2 != nil && len(in2.Answer)  == 0 {
				// se deu timeout no sistema de DNS hoje existente e o novo respondeu, mas com a resposta no valor zero
				// nós deixamos passar, pois não é um caso de erro
				continue
			}

			log.Printf("Erro ao enviar a questão DNS [%s] tipo %s, linha nº=%d, para o IP=[%s] com o erro [%s]", dnsQ.Name, dns.Type(dnsQ.Qtype).String(), lineNumber, IpAddress1, errExchange1.Error())
			continue
		}

		// faz o log do erro da 2ª requisição
		if errExchange2 != nil {
			log.Printf("Erro ao enviar a questão DNS [%s] tipo %s, linha nº=%d, para o IP=[%s] com o erro [%s]", dnsQ.Name, dns.Type(dnsQ.Qtype).String(), lineNumber, IpAddress2, errExchange2.Error())
			continue
		}

		// Compara se o slice do response são de tamanhos iguais
		// caso não seja grava em um arquivo as respostas para consulta
		if len(in1.Answer) != len(in2.Answer) {
			// gravar em um file as queries de respostas
			msg := fmt.Sprintf(timeNow() + " Os arrays da questão (%+v) e respostas [%+v] e [%+v] são de tamanhos diferentes.", m.Question, in1.Answer, in2.Answer)
			writeAnswerFile(msg)
			continue
		}

		if in1.Extra != nil && in2 != nil {
			if len(in1.Extra) != len(in2.Extra) {
				// gravar em um file as queries de respostas
				msg := fmt.Sprintf(timeNow() + " Os arrays de da questão (%+v) e Extras [%+v] e [%+v] são de tamanhos diferentes.", m.Question, in1.Extra, in2.Extra)
				writeAnswerFile(msg)
				continue
			}

			// Verifica utilizando a função DeepEqual se os as duas respostas são idênticas
			// caso não seja, grava em arquivo as respostas para consulta
			if !answerExist(in1.Extra, in2.Extra) {
				// gravar em um file as queries de respostas
				msg := fmt.Sprintf(timeNow() + " Os Extras não são idênticas [%+v] e [%+v]", in1.Extra, in2.Extra)
				writeAnswerFile(msg)
				continue
			}
		}
	}
}

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

// ignoreDomains ignora domínios da blacklist
func ignoreDomains(q string) bool {
	for _, domain := range IgnoreDomains {
		if strings.Contains(q, domain) {
			return true
		}
	}
	return false
}

// ignoreHexIPDomains
func ignoreHexIPDomains(questionDNS *QuestionDNS) bool {
	var qname string = questionDNS.Name
	var qtype string = dns.Type(questionDNS.Qtype).String()

	re := regexp.MustCompile(`^[a-f0-9]{8}[^a-z0-9]`)
	if re.MatchString(qname) && qtype == "TXT" {
		return true
	}

	return false
}

func timeNow() string {
	return time.Now().Format("02-Jan-2006 15:04:05")
}
