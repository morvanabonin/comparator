package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strconv"
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
const (
	IpAddress1 = "172.30.1.242" // IP do atual DNS
	Port1      = ":53"
	IpAddress2 = "127.0.0.1" // IP do serviço que ficará o novo DNS
	Port2      = ":53"
	ChannelQtd = 100
)

// testes
//const (
//	IpAddress1 = "192.168.101.117" // "172.30.1.242" IP do atual DNS
//	Port1      = ":53"
//	IpAddress2 = "192.168.101.117" // IP do serviço que ficará o novo DNS
//	Port2      = ":1553"
//	ChannelQtd = 1
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
		"18d5h68b5h252e772a-idc.ptt.diptt.com.br.",
	}

	IgnoreDomainsByInitialization = []string{
		"www.",
		"blog.",
		"tw.",
		"staging.",
		"home.", // Inicial de domínios a serem ignorados, considerado lixo
	}

	IgnoreTypes = []string{
		"ANY",
		"AAAA",
		"DHCID",
		"DNSKEY",
		"DS",
		"HIP",
		"HTTPS",
		"KEY",
		"NAPTR",
		"RT",
		"SIG",
		"SRV",
		"TLSA",
		"TYPE",
		"AFSDB",
		"APL",
		"CSYNC",
		"DNAME",
		"EUI48",
		"GPOS",
		"MF",
		"MG",
		"None",
		"NXT",
		"SMIMEA",
		"TA",
	}

	executeExchange chan QuestionDNS
	catchError      string
	catchError2     string
	waitCompare     sync.WaitGroup
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
	pathFile := "/var/log/dinamize/questions-dns/Questions-DNS.json"

	// testes
	// pathFile := "/var/log/dinamize/dev/morvana.bonin/dns-questions/Questions-DNS.json"

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

		// ignorar os domínios de blacklist
		if ignoreDomains(dnsQ.Name) {
			fmt.Printf("-")
			continue
		}

		// // ignora domínios como 'a0.meuspf.com.'
		if ignoreA0MeuSpfComDomain(dnsQ) {
			fmt.Printf("-")
			continue
		}

		// ignora domínios como o exemplo a seguir
		// 4.a.a.6.f.3.4.4.4.2.2.3.e.1.b.c.0.6.1.0.0.4.0.0.c.0.e.0.4.0.8.2.ip6.arpa.
		if ignoreDomainsIP6Arpa(dnsQ) {
			fmt.Printf("-")
			continue
		}

		if ignoreDomainsByInitialization(dnsQ.Name) {
			fmt.Printf("-")
			continue
		}

		if ignoreDomainsInitByExpression(dnsQ) {
			fmt.Printf("-")
			continue
		}

		// ignorar os tipos de DNS da lista
		dnsType := dns.Type(dnsQ.Qtype).String()
		if ignoreDNSTypes(dnsType) {
			fmt.Printf("-")
			continue
		}

		// ignorar os domínios que iniciam com certlets
		if ignoreCertlets(dnsQ.Name) {
			fmt.Printf("-")
			continue
		}

		// se o dnsQ.Name vier nesse padrão 05c49616-idc
		// e for do Tipo TXT
		// nos ignoraremos
		if ignoreHexIPDomains(dnsQ) {
			fmt.Printf("-")
			continue
		}

		// se o dnsQ.Name vier nesse padrão 172.108.127.128.
		// e for do Tipo A
		// nos ignoraremos
		if ignoreQuestionsInitIPs(dnsQ) {
			fmt.Printf("-")
			continue
		}

		// se o dnsQ.Name vier nesse padrão 8333.myrlk.com.
		// e for do Tipo A
		// nos ignoraremos
		if ignoreQuestionsInitNumber(dnsQ) {
			fmt.Printf("-")
			continue
		}

		// se o dnsQ.Name vier nesse padrão 11340.meuspf.com
		// e for do Tipo NS
		// nos ignoraremos
		if ignoreQuestionsInitNumberMeuSpf(dnsQ) {
			fmt.Printf("-")
			continue
		}

		// ignora as questões onde o domínio inicializa com essa expressão
		// ex.: 20385.meuspf.com.
		if verifiedQuestionsInitNumberAndMeuSpf(dnsQ) {
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
		// Ignora, também, tipos que não estamos prevendo ou mesmo não existem
		// Exemplo: TypeHINFO, TypeAXFR,...
		// pois CNAME é apenas para respostas
		if dnsQ.Qtype == 5 || dnsQ.Qtype == 252 || dnsQ.Qtype == 13 || dnsQ.Qtype == 64 {
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

		var in1 *dns.Msg
		var errExchange1 error
		// envia a pergunta passando o endereço ip e a porta
		clientDNS := new(dns.Client)
		clientDNS.Timeout = 3 * time.Second
		in1, _, errExchange1 = clientDNS.Exchange(m, IpAddress1+Port1)

		// caso dê erro de timeout, em relação ao sistema antigo, faz um novo reenvio
		if errExchange1 != nil && strings.Contains(errExchange1.Error(), "timeout") {
			in1, _, errExchange1 = clientDNS.Exchange(m, IpAddress1+Port1)
		}

		// ignoreWrongAnswerDMARC ignora respostas onde a pergunta inicial com _dmarc.
		// Tipo TXT
		// mas que no DNS antigo a resposta não contém
		// v=DMARC1;
		if ignoreWrongAnswerDMARC(dnsQ, in1) {
			fmt.Printf("-")
			waitCompare.Done()
			continue
		}

		// envia a mesma pergunta para outro endereço ip e porta
		var in2 *dns.Msg
		var errExchange2 error
		client2DNS := new(dns.Client)
		client2DNS.Timeout = 3 * time.Second
		in2, _, errExchange2 = client2DNS.Exchange(m, IpAddress2+Port2)

		// caso dê erro de timeout, faz um novo reenvio
		if errExchange2 != nil && strings.Contains(errExchange2.Error(), "timeout") {
			in2, _, errExchange2 = client2DNS.Exchange(m, IpAddress2+Port2)
		}

		// se erro nas duas respostas não for nil e os dois tiverem dado timeout, iremos considerar como igual.
		if errExchange1 != nil && errExchange2 != nil {
			if strings.Contains(errExchange1.Error(), "timeout") && strings.Contains(errExchange2.Error(), "timeout") {
				fmt.Printf("=")
				waitCompare.Done()
				continue
			}
		}

		if errExchange1 != nil && strings.Contains(errExchange1.Error(), "timeout") && in2 != nil && len(in2.Answer) == 0 {
			fmt.Printf("-")
			// se deu timeout no sistema de DNS hoje existente e o novo respondeu, mas com a resposta no valor zero
			// nós deixamos passar, pois, não consideramos como um caso de erro
			waitCompare.Done()
			continue
		}

		// log caso as duas questões deem erro ao fazer o exchange
		if errExchange1 != nil && errExchange2 != nil {
			fmt.Printf("x")

			msg := fmt.Sprintf(timeNow()+" Erro ao enviar a questão DNS [%s] tipo %s, para o IP=[%s] e o IP=[%s] com o erro [%s] e o erro [%s]",
				dnsQ.Name,
				dns.Type(dnsQ.Qtype).String(),
				IpAddress1,
				IpAddress2,
				errExchange1.Error(),
				errExchange2.Error())
			writeAnswerFile(msg)
			waitCompare.Done()
			continue
		}

		// faz o log do erro da 1ª requisição
		if errExchange1 != nil {
			fmt.Printf("x")

			msg := fmt.Sprintf(timeNow()+" Erro ao enviar a questão DNS [%s] tipo %s, para o IP=[%s] com o erro [%s]",
				dnsQ.Name,
				dns.Type(dnsQ.Qtype).String(),
				IpAddress1,
				errExchange1.Error())
			writeAnswerFile(msg)
			waitCompare.Done()
			continue
		}

		// faz o log do erro da 2ª requisição
		if errExchange2 != nil {
			fmt.Printf("x")

			msg := fmt.Sprintf(timeNow()+" Erro ao enviar a questão DNS [%s] tipo %s, para o IP=[%s] com o erro [%s]",
				dnsQ.Name,
				dns.Type(dnsQ.Qtype).String(),
				IpAddress2,
				errExchange2.Error())
			writeAnswerFile(msg)
			waitCompare.Done()
			continue
		}

		// ignoreNs1Ns2AsAnsweredAtLeastOnce
		// ignorar quando
		// houver no resposta do antigo sistema ns1.dnzdns.com. e ns2.dnzdns.com.
		// e quando no novo houver a resposta ns1.dnzdns.com. ou ns2.dnzdns.com.
		if ignoreNs1Ns2AsAnsweredAtLeastOnce(dnsQ, in1, in2) {
			fmt.Printf("-")
			waitCompare.Done()
			continue
		}

		// se vem resposta no antigo
		// se a resposta no novo é vazia
		// se é do tipo A
		if len(in1.Answer) > 0 && len(in2.Answer) == 0 && dnsQ.Qtype == 1 {
			stringAnswer := in1.Answer[0].String()
			re := regexp.MustCompile(`^[a-z0-9]{8}`)

			match := re.FindString(stringAnswer)

			if match != "" {
				if ignoreDomainsTurnedInHexWrong(dnsQ.Name, stringAnswer) {
					fmt.Printf("=")
					waitCompare.Done()
					continue
				}
			}
		}

		// se a pergunta for do tipo A e a resposta do novo DNS contiver o IP 13.59.106.13
		// e o len da respostas do antigo for igual a 2
		if dnsQ.Qtype == 1 && len(in1.Answer) == 2 && len(in2.Answer) == 1 {
			stringAnswer := in2.Answer[0].String()
			if strings.Contains(stringAnswer, "13.59.106.13") {
				fmt.Printf("-")
				waitCompare.Done()
				continue
			}
		}

		// se a pergunta é do tipo TXT e o antigo sistema de DNS respondeu "v=spf1 ?all"
		// e o novo não teve resposta, considerar como iguais.
		if dnsQ.Qtype == 16 && len(in1.Answer) == 1 && len(in2.Answer) == 0 {
			fmt.Printf("=")
			waitCompare.Done()
			continue
		}

		// se a pergunta é do tipo A e a resposta contiver os seguintes IPs
		// 18.189.133.24 resposta do antigo
		// 18.189.133.24 e 3.132.188.189 resposta do novo
		// ns1.dnzdns.com.		86400	IN	A	18.189.133.24
		// ns1.dnzdns.com.		86400	IN	A	3.132.188.189
		if dnsQ.Qtype == 1 && len(in1.Answer) == 1 && len(in2.Answer) == 2 {
			stringAnswer := in1.Answer[0].String()
			stringAnswer2 := in2.Answer[0].String()
			stringAnswer2 += in2.Answer[1].String()
			if strings.Contains(stringAnswer, "18.189.133.24") &&
				strings.Contains(stringAnswer2, "18.189.133.24") &&
				strings.Contains(stringAnswer2, "3.132.188.189") {
				fmt.Printf("=")
				waitCompare.Done()
				continue
			}
		}

		// se a pergunta é do tipo A e a resposta contiver os seguintes IPs
		// 3.139.183.150 resposta do antigo
		// 18.190.44.139 e 3.139.183.150 resposta do novo
		// ns2.dnzdns.com.		86400	IN	A	3.139.183.150
		// ns2.dnzdns.com.		86400	IN	A	18.190.44.139
		if dnsQ.Qtype == 1 && len(in1.Answer) == 1 && len(in2.Answer) == 2 {
			stringAnswer := in1.Answer[0].String()
			stringAnswer2 := in2.Answer[0].String()
			stringAnswer2 += in2.Answer[1].String()
			if strings.Contains(stringAnswer, "3.139.183.150") &&
				strings.Contains(stringAnswer2, "18.190.44.139") &&
				strings.Contains(stringAnswer2, "3.139.183.150") {
				fmt.Printf("=")
				waitCompare.Done()
				continue
			}
		}

		// Hoje o sistema atual coloca máscara ao retornar a resposta SPF1
		// o DNS novo não, apenas retorna o IP
		// essa excessão é para tratar como igual quando for esse caso
		// exemplo de questão feita _mta-sts.5cde83b1-idc.cli.dnzpark.com.br.
		// exemplo de resposta
		// DNS atual 5cde83b1-idc.cli.dnzpark.com.br.	86400	IN	TXT	"v=spf1 mx ip4:92.222.131.128/26 -all"
		// DNS novo _mta-sts.5cde83b1-idc.cli.dnzpark.com.br.	86400	IN	TXT	"v=spf1 ip4:92.222.131.177 -all"
		if dnsQ.Qtype == 16 && len(in1.Answer) == 1 && len(in2.Answer) == 1 {
			stringAnswer := in1.Answer[0].String()
			stringAnswer2 := in2.Answer[0].String()

			re := regexp.MustCompile(`([0-9a-f]{8})`)

			match := re.FindString(stringAnswer)
			match2 := re.FindString(stringAnswer2)
			if match == match2 {
				if strings.Contains(stringAnswer, "/26 -all") {
					fmt.Printf("=")
					waitCompare.Done()
					continue
				}
			}
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

		// ignoreGarbageMyrlkDomain
		// if qName tem 1631878458828.myrlk.com., qType = 1 e nas repostas do antigo sistema tiver os IPs 18.189.133.24 e 3.139.183.150
		// e a resposta do novo sistema for nil, ignora como sendo certo.
		if ignoreGarbageMyrlkDomain(dnsQ, in1, in2) {
			fmt.Printf("-")
			waitCompare.Done()
			continue
		}

		// ignoreWhenOldDNSNotDMARCAnswered
		// ignorar quando o antigo não responder, mas o novo responder com a seguinte resposta
		// "v=DMARC1;p=reject;"
		if ignoreWhenOldDNSNotDMARCAnswered(dnsQ, in1, in2) {
			fmt.Printf("-")
			waitCompare.Done()
			continue
		}

		// se o tipo for A e a resposta do sistema antigo for maior que 0 e
		// a resposta do DNS novo for igual a 0, ignorar
		if dnsQ.Qtype == 1 && len(in1.Answer) > 0 && len(in2.Answer) == 0 {
			stringAnswer := in1.Answer[0].String()
			if strings.Contains(stringAnswer, "5.135.3.208") {
				fmt.Printf("-")
				waitCompare.Done()
				continue
			}
		}

		// Fazer no comparator, considerando =
		// Se a pergunta é TXT e a resposta do antigo é "v=spf1 mx ip4:5.135.3.208/32 ip4:5.135.3.209/32 -all"
		// e a do novo "v=spf1 ip4:5.135.3.208/31 ~all" considerar que o resultado é =
		if len(in1.Answer) > 0 && len(in2.Answer) > 0 {
			if ignoreIPInSPFAnswer(in1.Answer[0].String(), in2.Answer[0].String()) {
				fmt.Printf("=")
				waitCompare.Done()
				continue
			}
		}

		// Se a pergunta é TXT e a resposta do antigo é "v=spf1 mx ip4:5.135.3.208/32 ip4:5.135.3.240/28 -all"
		// e a do novo "v=spf1 ip4:5.135.3.192/26 ~all" considerar que o resultado é =
		if len(in1.Answer) > 0 && len(in2.Answer) > 0 {
			if ignoreIPinSPFAnswerMeuSPFDomain(in1.Answer[0].String(), in2.Answer[0].String()) {
				fmt.Printf("=")
				waitCompare.Done()
				continue
			}
		}

		// Ignorar IP e máscara 108.163.219.0/28 quando este vier diferente,
		// pois o sistema novo faz o cálculo com maior assertividade
		if len(in1.Answer) > 0 && len(in2.Answer) > 0 {
			if ignoreIPInSPFAnswerWhenMaskWrong(in1.Answer[0].String(), in2.Answer[0].String()) {
				fmt.Printf("=")
				waitCompare.Done()
				continue
			}
		}

		// Ignorar IP e máscara 5.39.121.128/25 quando este vier diferente,
		// pois o sistema novo faz o cálculo com maior assertividade
		if len(in1.Answer) > 0 && len(in2.Answer) > 0 {
			if ignoreIPInSPFAnswerWhenMaskWrong2(in1.Answer[0].String(), in2.Answer[0].String()) {
				fmt.Printf("=")
				waitCompare.Done()
				continue
			}
		}

		// Compara se o slice do response são de tamanhos iguais
		// caso não sejam iguais grava em um arquivo as respostas para consulta
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

		// Verifica se as duas respostas são idênticas
		// caso não seja, grava em arquivo as respostas para consulta
		if !answerExist(in1.Answer, in2.Answer) {

			// Aqui vai à lógica de caso seja diferente as respostas, mas essa for do tipo TXT e v=spf1
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
			msg := fmt.Sprintf("As respostas da questão (%+v) não são idênticas [%+v] e [%+v]", m.Question, in1.Answer, in2.Answer)
			writeAnswerFile(msg)
			waitCompare.Done()
			continue
		}

		// Verifica se veio Extra no retorno do DNS
		if in1.Extra != nil && in2.Extra != nil {

			if len(in1.Extra) != len(in2.Extra) {

				// se o conjunto da sessão adicional das respostas (conhecido como Extras) de IPs do antigo DNS
				// for menor que do atual DNS então verifica se os valores que vieram no novo estão contidos no DNS antigo,
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

			// Verifica se os dois Extras são idênticos
			// caso não seja, grava em arquivo as respostas para consulta
			if !answerExist(in1.Extra, in2.Extra) {
				fmt.Printf("!")

				// gravar em um file as queries de respostas
				msg := fmt.Sprintf(timeNow()+" Os Extras da questão (%+v) não são idênticas [%+v] e [%+v]", m.Question, in1.Extra, in2.Extra)
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

// ignoreIPInSPFAnswer
// Fazer no comparator, considerando =
// Se a pergunta é TXT e a resposta do antigo é "v=spf1 mx ip4:5.135.3.208/32 ip4:5.135.3.209/32 -all"
// e a do novo "v=spf1 ip4:5.135.3.208/31 ~all" considerar que o resultado é =
func ignoreIPInSPFAnswer(resp1, resp2 string) bool {
	if strings.Contains(resp1, "5.135.3.208") && strings.Contains(resp2, "5.135.3.208") {
		return true
	}
	return false
}

// ignoreIPinSPFAnswerMeuSPFDomain
// considerando =
// Se a pergunta é TXT e a resposta do antigo são "v=spf1 mx ip4:5.135.3.208/32 ip4:5.135.3.240/28 -all"
// e a do novo "v=spf1 ip4:5.135.3.192/26 ~all" considerar que o resultado é =
func ignoreIPinSPFAnswerMeuSPFDomain(resp1, resp2 string) bool {
	if strings.Contains(resp1, "ip4:5.135.3.208/32 ip4:5.135.3.240/28") && strings.Contains(resp2, "ip4:5.135.3.192") ||
		strings.Contains(resp1, "ip4:5.135.3.207/32 ip4:5.135.3.208/32") && strings.Contains(resp2, "ip4:5.135.3.192") ||
		strings.Contains(resp1, "ip4:5.135.3.208/32 ip4:5.135.3.224/28") && strings.Contains(resp2, "ip4:5.135.3.192") ||
		strings.Contains(resp1, "ip4:5.135.3.192/28 ip4:5.135.3.208/32") && strings.Contains(resp2, "ip4:5.135.3.192") ||
		strings.Contains(resp1, "ip4:5.135.3.206/32 ip4:5.135.3.208/32") && strings.Contains(resp2, "ip4:5.135.3.206") {
		return true
	}
	return false
}

// ignoreIPInSPFAnswerWhenMaskWrong
// Ignorar IP e máscara 108.163.219.0/28 quando este vier diferente,
// pois o sistema novo faz o cálculo com maior assertividade
func ignoreIPInSPFAnswerWhenMaskWrong(resp1, resp2 string) bool {
	if strings.Contains(resp1, "108.163.219.0/28") && strings.Contains(resp2, "108.163.219.0/29") {
		return true
	}
	return false
}

// ignoreIPInSPFAnswerWhenMaskWrong2
// Ignorar IP e máscara 5.39.121.128/25 quando este vier diferente,
// pois o sistema novo faz o cálculo com maior assertividade
func ignoreIPInSPFAnswerWhenMaskWrong2(resp1, resp2 string) bool {
	if strings.Contains(resp1, "5.39.121.128/25") && strings.Contains(resp2, "5.39.121.128/26") {
		return true
	}
	return false
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

// ignoreDomainsIP6Arpa
func ignoreDomainsIP6Arpa(questionDNS QuestionDNS) bool {
	if strings.Contains(questionDNS.Name, ".ip6.arpa.") && questionDNS.Qtype == 12 {
		return true
	}
	return false
}

// ignoreDomainsByInitialization ignore domínios de que inicializam com
// www.
// blog.
// tw.
// staging.
// home.
func ignoreDomainsByInitialization(q string) bool {
	for _, prefix := range IgnoreDomainsByInitialization {
		if strings.HasPrefix(q, prefix) {
			return true
		}
	}
	return false
}

// ignoreDomainsInitByExpression ignora as questões onde o domínio inicializa com uma expressão,
// devido ao sistema antigo responder com o ip da expressão
// ex.: mta-sts.8F0C56.po.prodina.com.br.
func ignoreDomainsInitByExpression(questionDNS QuestionDNS) bool {
	var (
		qname = questionDNS.Name
		qtype = dns.Type(questionDNS.Qtype).String()
	)

	re := regexp.MustCompile(`\.[a-f0-9]{8}\.`)
	if re.MatchString(qname) && qtype == "A" {
		return true
	}

	return false
}

// ignoreDNSTypes ignora domínios de tipos que não iremos ler
func ignoreDNSTypes(qType string) bool {
	for _, typ := range IgnoreTypes {
		if strings.Contains(qType, typ) {
			return true
		}
	}
	return false
}

// ignoreCertlets ignora questões que tenham a regra certlets.
func ignoreCertlets(q string) bool {
	return strings.HasPrefix(q, "certlets.")
}

// ignoreWrongAnswerDMARC ignora respostas onde a pergunta inicial com _dmarc.
// tipo TXT
// mas que no DNS antigo a resposta não contém
// v=DMARC1;
func ignoreWrongAnswerDMARC(dnsQ QuestionDNS, ans1 *dns.Msg) bool {
	resp := ""
	if ans1 != nil && ans1.Answer != nil {
		resp = ans1.Answer[0].String()
	}
	if strings.HasPrefix(dnsQ.Name, "_dmarc.") &&
		dnsQ.Qtype == 16 && !strings.Contains(resp, "v=DMARC1;") {
		return true
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

// ignoreQuestionsInitIPs ignora as questões onde o domínio inicializa com um endereço de IP
// ex.: 201.108.127.128.smtp.dnsbl.sorbs.net.po.prodina.com.br.
func ignoreQuestionsInitIPs(questionDNS QuestionDNS) bool {
	var (
		qname = questionDNS.Name
		qtype = dns.Type(questionDNS.Qtype).String()
	)

	re := regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.`)
	if re.MatchString(qname) && qtype == "A" {
		return true
	}

	return false
}

// ignoreQuestionsInitNumber ignora as questões onde o domínio inicializa com essa expressão
// ex.: 8333.myrlk.com.
func ignoreQuestionsInitNumber(questionDNS QuestionDNS) bool {
	var (
		qname = questionDNS.Name
		qtype = dns.Type(questionDNS.Qtype).String()
	)

	re := regexp.MustCompile(`^[0-9]{1,7}\.myrlk\.com`)
	if re.MatchString(qname) && qtype == "A" {
		return true
	}

	return false
}

// verifiedQuestionsInitNumberAndMeuSpf ignora as questões onde o domínio inicializa com essa expressão
// ex.: 20385.meuspf.com.
func verifiedQuestionsInitNumberAndMeuSpf(questionDNS QuestionDNS) bool {
	var (
		qname = questionDNS.Name
		qtype = dns.Type(questionDNS.Qtype).String()
	)

	re := regexp.MustCompile(`^[0-9]{1,7}\.meuspf\.com`)
	if re.MatchString(qname) && qtype == "TXT" {
		return true
	}

	return false
}

// ignoreQuestionsInitNumberMeuSpf ignora as questões onde o domínio inicializa com essa expressão
// ex.: 11340.meuspf.com
func ignoreQuestionsInitNumberMeuSpf(questionDNS QuestionDNS) bool {
	var (
		qname = questionDNS.Name
		qtype = dns.Type(questionDNS.Qtype).String()
	)

	re := regexp.MustCompile(`^[0-9]{1,7}\.meuspf\.com`)
	if re.MatchString(qname) && qtype == "NS" {
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
// Aqui vai à lógica de caso seja diferente as respostas, mas essa for do tipo TXT e v=spf1
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

// arrayIps pega a string e com uma regex retira apenas os valores em IPs
// depois faz um split por espaço e retorna
// um slice [ip4:195.195.1.0/25]
func arrayIps(v string) []string {
	re := regexp.MustCompile("ip4:.*/[0-9]{2}")
	ipsFound := re.FindString(v)
	r := strings.Split(ipsFound, " ")
	return r
}

// orderAndCompare faz comparação entre os IPs retornados na resposta do tipo TXT
// [ip4:192.168.101.0/32 ip4:195.195.0.0/25 ip4:195.195.1.0/25 ip4:195.195.2.0/26 ip4:195.195.4.0/26]
func orderAndCompare(ips1, ips2 []string) bool {
	var exist []bool
	var check []bool

	for range ips2 {
		check = append(check, false)
	}

	for i, ip1 := range ips1 {
		exist = append(exist, false)

		// como o novo sistema de DNS não coloca mais o /32 por se tratar do IP mesmo,
		// é retirado da resposta do sistema antigo para então comparar
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

// ignoreDomainsTurnedInHexWrong função que pega a questão e as respostas e compara
// se a questão passada é transformada em um IP e este IP veio na resposta do sistema antigo,
// ou seja, os IPs são iguais e o sistema novo não respondeu nada, retorna como igual, pois, o
// sistema antigo converteu um domínio que não deveria ser convertido em IP.
// Caso retorne NIL, o retorno é false.
// s = dnsQ.Name
// resp = in1.Answer
func ignoreDomainsTurnedInHexWrong(s string, resp string) bool {
	IPFound := getIPFromAnswer(resp)

	host := strings.Split(s, ".")
	if len(host) < 1 {
		return false
	}

	hexa := host[0]
	if len(hexa) != 8 {
		return false
	}

	rIP0, err := strconv.ParseUint(hexa[0:2], 16, 64)
	if err != nil {
		return false
	}
	rIP1, err := strconv.ParseUint(hexa[2:4], 16, 64)
	if err != nil {
		return false
	}
	rIP2, err := strconv.ParseUint(hexa[4:6], 16, 64)
	if err != nil {
		return false
	}
	rIP3, err := strconv.ParseUint(hexa[6:8], 16, 64)
	if err != nil {
		return false
	}

	IPAddress := net.IP([]byte{byte(rIP0), byte(rIP1), byte(rIP2), byte(rIP3)})

	if IPAddress.Equal(IPFound) {
		return true
	}

	return false
}

func getIPFromAnswer(resp string) net.IP {
	re := regexp.MustCompile(`[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$`)
	ipFound := re.FindString(resp)
	IPAddress := net.ParseIP(ipFound)
	return IPAddress
}

// ignoreGarbageMyrlkDomain
// if qName tem 1631878458828.myrlk.com., qType = 1 e nas repostas do antigo sistema tiver os IPs 18.189.133.24 e 3.139.183.150
// e a resposta do novo sistema for nil, ignora como sendo certo.
func ignoreGarbageMyrlkDomain(questionDNS QuestionDNS, in1, in2 *dns.Msg) bool {
	stringAnswer := in1.Answer[0].String()
	stringAnswer += in1.Answer[1].String()
	if questionDNS.Qtype == 1 &&
		strings.Contains(stringAnswer, "18.189.133.24") &&
		strings.Contains(stringAnswer, "3.139.183.150") &&
		len(in2.Answer) == 0 {
		return true
	}
	return false
}

// ignoreNs1Ns2AsAnsweredAtLeastOnce
// ignorar quando
// houver no resposta do antigo sistema ns1.dnzdns.com. e ns2.dnzdns.com.
// e quando no novo houver a resposta ns1.dnzdns.com. ou ns2.dnzdns.com.
func ignoreNs1Ns2AsAnsweredAtLeastOnce(questionDNS QuestionDNS, in1, in2 *dns.Msg) bool {
	stringAnswer := in1.Answer[0].String()
	stringAnswer += in1.Answer[1].String()
	string2Answer := in2.Answer[0].String()
	if questionDNS.Qtype == 2 &&
		strings.Contains(stringAnswer, "ns1.dnzdns.com.") &&
		strings.Contains(stringAnswer, "ns2.dnzdns.com.") &&
		(strings.Contains(string2Answer, "ns1.dnzdns.com.") || strings.Contains(string2Answer, "ns2.dnzdns.com.")) {
		return true
	}
	return false
}

// ignoreA0MeuSpfComDomain
// ignora domínios como 'a0.meuspf.com.'
func ignoreA0MeuSpfComDomain(questionDNS QuestionDNS) bool {
	qName := strings.ToLower(questionDNS.Name)
	if questionDNS.Qtype == 16 && strings.Contains(qName, "a0.meuspf.com.") {
		return true
	}
	return false
}

// ignoreWhenOldDNSNotDMARCAnswered
// ignorar quando o antigo não responder, mas o novo responder com a seguinte resposta
// "v=DMARC1;p=reject;"
func ignoreWhenOldDNSNotDMARCAnswered(questionDNS QuestionDNS, in1, in2 *dns.Msg) bool {
	stringAnswer := in2.Answer[0].String()
	if questionDNS.Qtype == 16 && len(in1.Answer) == 0 &&
		strings.Contains(stringAnswer, "v=DMARC1;p=reject;") {
		return true
	}
	return false
}
