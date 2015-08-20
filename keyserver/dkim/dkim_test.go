package dkim

import (
	"strings"
	"testing"
	"time"
)

var testSignupYahooInc = strings.Replace(`X-Apparently-To: andreser@yahoo-inc.com; Tue, 18 Aug 2015 20:42:53 +0000
Return-Path: <andreser@yahoo-inc.com>
Received-SPF: pass (domain of yahoo-inc.com designates 98.139.253.105 as permitted sender)
X-YMailISG: 4H.Eg1AWLDshYuXjmhSOGiZr.ukuTFQZthvp2psWJFCbZsRS
 x3vZaJzyeE09yyR5MRlSh19EJSK1amHGOykYCJPtnC55iL2K798cZ6r8gL.R
 14eNjcUBKJYx7R15v4DG01VVqE.MoIqwOyY5V3117gVE92R.BPNFHGejXWGs
 ArdL.IYFHloGf6QtKgboEElJaIKKzTil4ASHgA.FkGrrfD42.kt4S7tWRwFB
 xy1gaa8aN5M24bh6A7JobXAja38.PiM5eBfdvvXrUO08BHpJKFwBT0a.bH2e
 SPWiFqsHWl7dfegRRRdJ2PIq.4LJhVoF8n35skRPi1ADaOKQOye61jhYYuyk
 r_pyI4RgD1a0UcO2d8zIMts4gKz8Qs6yvYJGfqNtEGMJoizcObIA.9vDPhuw
 ZHNJqoSQgXj8fDz5o.Ey0Q_kgCoepd29psUtiZmANIEth5ZIcKlJcwbbjy3T
 emA1ErnnbVIl_a1FtfGFpxn60SI_PC7GQMgcc8En58ewLxq8pjezXojjooZl
 kH2Y_5ygaPHix6P.jxRUPT75w7Xq55AoRIWiLG.yfVlMgJoxxwh_ENc5MmsT
 GTJ87t1.NZgiPxtS1IE3WOXHgrFSZfqeBrcF6hAlEbf1Z1wCb2oTJi5e3f8U
 bwXVNrv074iqCIFU3YzJYVyMjs8u74UNlsenPy8Ge3E_qA6P0EOFOdDZGjc8
 WTrjVNFDi9m.8zYNxEUxVIQXf9tiBM1i_eS15c4F1gpfhumYAcyjjEUtImt7
 9EXhzMYgEzjrK99dJjbJOPb6aEVL.MIP6m6BbYBXJGGDtasNjV2ExzR.WUZe
 teGHeEfsBECMz9gyVFNx.so25l28mUJlgkdpN4GvwsB4axWwrgMZozOQNUk0
 dy5FZONqFlhkFO_1Iiany.GPZAwT9_kHyKcw5DgdmR_FxaBpRYCmtFNhu8VH
 c_UgLqv9H289cA9WnAsD9kC8ZlOff9LRnzOzPfbUYp26iVWe31mT3JtI3Dsh
 Hwv41AUaAU.1SFFyvyGZ0bKWd.Wfb.cvHNdUoEoM9s18CPfyZRUF2Obz2rxn
 wzxzQWSGvQi_TLisMSquvnfY1.xdXLgvPwhKIG_ms4DEKA4hvrCYKdNGdiOJ
 YjcImIcvAViLBWcpFomQ_19Nm18wWsx1ZvgkcGEy0hgxhHaEuvKovOOXWBTW
 c6CcYwAap06RCM.MgnzSS60F13mu3jExrT2KhE20SC6V5ByBQmAvZNy1PX3Z
 IOrqGkb.Mw--
X-Originating-IP: [98.139.253.105]
Authentication-Results: mta2003.corp.mail.bf1.yahoo.com  from=yahoo-inc.com; domainkeys=neutral (no sig);  from=yahoo-inc.com; dkim=pass (ok)
Received: from 127.0.0.1  (EHLO mrout2-b.corp.bf1.yahoo.com) (98.139.253.105)
  by mta2003.corp.mail.bf1.yahoo.com with SMTPS; Tue, 18 Aug 2015 20:42:53 +0000
Received: from omp1009.mail.ne1.yahoo.com (omp1009.mail.ne1.yahoo.com [98.138.87.9])
	by mrout2-b.corp.bf1.yahoo.com (8.14.4/8.14.4/y.out) with ESMTP id t7IKgNFC047854
	(version=TLSv1/SSLv3 cipher=DHE-RSA-CAMELLIA256-SHA bits=256 verify=NO)
	for <andreser@yahoo-inc.com>; Tue, 18 Aug 2015 13:42:23 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; d=yahoo-inc.com;
	s=cobra; t=1439930544;
	bh=wSOlpwNdvuh7ASwe8kMl2zcIZaTvwjfvIkiDCv7mu4M=;
	h=Date:From:Reply-To:To:Subject;
	b=u0jCHxYPlqyv5JWJ7UUQzSZ+u8miWPy2UTHn8XjJhiDtcredJU2mgmY9mTDvS3cnc
	 AhphVjQoWxXo2ujCWvXq/qEAtutL57tx/BmlxoHl+xZSzktIhg86mRM3ZsU72sOgXn
	 roGDLZul0j7lO1w5yEkR+jcqGiPDojkN0zkZj6ms=
Received: (qmail 64596 invoked by uid 1000); 18 Aug 2015 20:42:23 -0000
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=yahoo-inc.com; s=ginc1024; t=1439930543; bh=wSOlpwNdvuh7ASwe8kMl2zcIZaTvwjfvIkiDCv7mu4M=; h=Date:From:Reply-To:To:Message-ID:Subject:MIME-Version:Content-Type; b=pLRuDb0JeozOzcJYibscIdG9yA3d3wGM+4VO+9kN4ivs/fBatmck++TKZCrSOKyhIDmCWEc6qcGwolFv9aJhZP/GyEYqktLg1o9joHsh8fSolhATKs7A4+OWzYL/wjDtyoU1fkZ3Il9sZa827FqeT5/6zzwPEW96STpKnlFAnQM=
X-YMail-OSG: LEY4mhYLUzsqF6ydcxLYdVlcfauuspaC3ErGVBThq_MLA5WYhgDMgjMf3VTEBvm
 .C_k-
Received: by 98.138.105.225; Tue, 18 Aug 2015 20:42:22 +0000 
Date: Tue, 18 Aug 2015 20:42:22 +0000 (UTC)
From: Andres Erbsen <andreser@yahoo-inc.com>
Reply-To: Andres Erbsen <andreser@yahoo-inc.com>
To: Andres Erbsen Erbsen <andreser@yahoo-inc.com>
Message-ID: <1153835905.3822924.1439930542436.JavaMail.yahoo@mail.yahoo.com>
Subject: E2ETEST: fsadfasdfasdfas2231
MIME-Version: 1.0
Content-Type: multipart/alternative; 
	boundary="----=_Part_3822923_1084555678.1439930542434"
Content-Length: 550

------=_Part_3822923_1084555678.1439930542434
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 7bit



------=_Part_3822923_1084555678.1439930542434
Content-Type: text/html; charset=UTF-8
Content-Transfer-Encoding: 7bit

<html><body><div style="color:#000; background-color:#fff; font-family:HelveticaNeue-Light, Helvetica Neue Light, Helvetica Neue, Helvetica, Arial, Lucida Grande, sans-serif;font-size:16px"><div id="yui_3_16_0_1_1439919878905_5194"><br></div></div></body></html>
------=_Part_3822923_1084555678.1439930542434--`, "\n", "\r\n", -1)
var yIncTXT = func(string) ([]string, error) {
	return []string{"v=DKIM1; g=*; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDGDd1Fz/AblN4d1haW+4B/u8PXkpd/s/JFkCPqp0Zk8xZ/SEs15fsWmj7yZwfsgi04Bs1eJhUIGf0iufHvkK5ws5XKBfbw1hYBHexopqYT5JFERYJ3slNEG5EeB04kKWpECjoMkXhDWvUJrHaBqGAz2KQ1dKAzrtKqRN2IVcDbBQIDAQAB"}, nil
}
var yIncTime = func() time.Time { return time.Unix(1439925628, 0) }

func TestYahooIncSignup(t *testing.T) {
	email, data, err := CheckEmailProof([]byte(testSignupYahooInc), "", "E2ETEST: ", yIncTXT, yIncTime)
	if err != nil {
		t.Error(err)
	}
	if want, got := "andreser@yahoo-inc.com", email; got != want {
		t.Errorf("got %q (wanted %q)", got, want)
	}
	if want, got := "fsadfasdfasdfas2231", data; got != want {
		t.Errorf("got %q (wanted %q)", got, want)
	}
}

func TestRejectChangedKey(t *testing.T) {
	pf := strings.Replace(testSignupYahooInc, "fsadfasdfasdfas2231", "FORGED", -1)
	email, data, err := CheckEmailProof([]byte(pf), "", "E2ETEST: ", yIncTXT, yIncTime)
	if err == nil {
		t.Error("forgery passed")
	}
	if email != "" {
		t.Error("forgery returned an email")
	}
	if data != "" {
		t.Error("forgery returned some data")
	}
}

func TestRejectChangedEmail(t *testing.T) {
	pf := strings.Replace(testSignupYahooInc, "andreser", "erandres", -1)
	email, data, err := CheckEmailProof([]byte(pf), "", "E2ETEST: ", yIncTXT, yIncTime)
	if err == nil {
		t.Error("forgery passed")
	}
	if email != "" {
		t.Error("forgery returned an email")
	}
	if data != "" {
		t.Error("forgery returned some data")
	}
}

var testYahooIncTo = strings.Replace(`X-Apparently-To: andreser@yahoo-inc.com; Tue, 18 Aug 2015 21:02:47 +0000
Return-Path: <andreser@yahoo-inc.com>
Received-SPF: pass (domain of yahoo-inc.com designates 98.139.253.105 as permitted sender)
X-YMailISG: cIVyQDgWLDulpYMXGVadLLsw3LpzNsTzMav0Y1P7bsKZm2Tx
 BAXuJyCmjbsotGnk90CPNrSBTP1edOuR7_YunKxQJ82F6MbmOsd8pobPXnrb
 .mdsi8IpBb6gx1kMqOcJFgYbQAFXLA4vbo88vsW70FLSD803wmDtAlwj95La
 3KZ2FzAcbloPvVAdUFb_qznYVWpKHQxXucN88izteOp3r5ILh5eRnl7LQ5XO
 WmQ5dxFfruw91KrIIiz6Ht30YeYVzzgkXmvAaQyryYdkBC2PQNv3ND69EDYs
 vqX0NHDVQML5wGmRYL6.ORjXSRfC2neHb0Xff.VY06NpSJeWBqMY2vWk2Tsw
 Egbyoo.LGqUEmyHVtaSnhBa_YE5ECSykPwq02.uj_dscWuzGBVRE1tZH2spH
 mYXtVUBLBbktsgKSW32BoYERZ.xrj7.G2eu4Z4PWJ.4QG7HeTZIBvrn7P_pQ
 2aXV0cnRE48hPS_VG6F7..ktjSDKuTB5OhfKaTlvn2SsV4xufi2erOk0SB60
 eTYFfr_IN.6ShiJNgrh0ZdU_Mc_5ehytYtuJk8IQqSkowWOGQOLVBhC797Wk
 5fT9wmr76Fjm1JapvdcZNPcbYJ3yrPZ0kr2vsfoGblmOTTWdfMmEgVGtOO.2
 j1OfDnnzufxXGR_WyeyPfSxdrciNxGEYLrp4yfWcs6VH3KIUzeHf6Kd4q_E4
 3gc8a117vkuQwB5FuCY403lqy5Gf3EiJ2v82adtHS4zE9_Ctsik2MYKBfFke
 3FRT_j7_b_xKVJVYP4r53j_XP4q06RinM8t6hLKccMI3CdPdXnTiwlMaZZFK
 5f8ux46HJBFlT7byvDBNPZhpK2ap7AlXUP3v1fYiclu9vaT4fk4f179ucBDv
 9TSFPwCw4FLTIzMO7syrxnzj_hWRPfYcupz3GJfCnfWGCCYzHljJDLNb1oK4
 ORPPTMX8bhkRdatmRyFBS2VBFIkacqn1THK.0MMNo.TgwByN1yugSk7tsidj
 ktp.4Y84xUVEDY.W20pMFaJmNjclPQulcMzMmdL01r1WE2.BF4BqqG5G8_k5
 oD3ywj6b9UsyMnKmmpBgGOkuVIM4v7DnaqFs8JlZbElnDL.wtWzfMrOQJsxX
 wFP8mgta98cr9oFS0efxwP8GhYRcNzhkdqW.0GDNiRk00jS_IC5lTqjCigCu
 t337RwojZGVJuMJjn3bpCbBcCI4xWIlCkQcTehnLFHZgczrYvlpd.PIaP3EC
 tUZIPqsY6mGJ9qFr.A--
X-Originating-IP: [98.139.253.105]
Authentication-Results: mta2005.corp.mail.bf1.yahoo.com  from=yahoo-inc.com; domainkeys=neutral (no sig);  from=yahoo-inc.com; dkim=pass (ok)
Received: from 166.78.68.213  (EHLO mrout2-b.corp.bf1.yahoo.com) (98.139.253.105)
  by mta2005.corp.mail.bf1.yahoo.com with SMTPS; Tue, 18 Aug 2015 21:02:47 +0000
Received: from omp1041.mail.ne1.yahoo.com (omp1041.mail.ne1.yahoo.com [98.138.89.249])
	by mrout2-b.corp.bf1.yahoo.com (8.14.4/8.14.4/y.out) with ESMTP id t7IL1vl4059967
	(version=TLSv1/SSLv3 cipher=DHE-RSA-CAMELLIA256-SHA bits=256 verify=NO)
	for <andreser@yahoo-inc.com>; Tue, 18 Aug 2015 14:01:58 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; d=yahoo-inc.com;
	s=cobra; t=1439931718;
	bh=qli7Att6sU4P21DtGcqQy5IbUUZLlDBZ3iAFuZQHRFg=;
	h=Date:From:Reply-To:To:Subject;
	b=wVz6cGtH8KGTcYsMsFv+rmoGU6YavkhVk4nlpyeQtG5xBOk6Mvbz8SOdBUsOFh6wm
	 kjWrRKWzowUZ66qkArW93THtS4cWw/M4cts0g0kRBxIwVyTvhkFd7T/+eQMNxKclOu
	 4ufohSeuvtZd6YlP8GGuL3u+Hrm7OppS7G9IS3GA=
Received: (qmail 51288 invoked by uid 1000); 18 Aug 2015 21:01:57 -0000
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=yahoo-inc.com; s=ginc1024; t=1439931717; bh=qli7Att6sU4P21DtGcqQy5IbUUZLlDBZ3iAFuZQHRFg=; h=Date:From:Reply-To:To:Message-ID:Subject:MIME-Version:Content-Type; b=qGvY+PnN4UtOxt7qIwkQDrPWIXV+zwk/u4TzBiSfxNu9oA5IzbVy/6s26dtgyESHMSqsNIGUix58g48CeGSeVKlbXLEbbUVfPAlsGnNy6al3uZa1/30DEDKsUjgjhQ5Nr5ddmmYf5Pb7rgfCJMYZw81Hojo370jqYI5wUSI5Sds=
X-YMail-OSG: LEY4mhYLUzsqF6ydcxLYdVlcfauuspaC3ErGVBThq_MLA5WYhgDMgjMf3VTEBvm
 .C_k-
Received: by 98.138.105.251; Tue, 18 Aug 2015 21:01:57 +0000 
Date: Tue, 18 Aug 2015 21:01:56 +0000 (UTC)
From: Andres Erbsen <andreser@yahoo-inc.com>
Reply-To: Andres Erbsen <andreser@yahoo-inc.com>
To: Andres Erbsen Erbsen <andreser@mit.edu>,
        Andres Erbsen Erbsen <andreser@yahoo-inc.com>
Message-ID: <748588213.6897778.1439931716940.JavaMail.yahoo@mail.yahoo.com>
Subject: E2ETEST: 12345
MIME-Version: 1.0
Content-Type: multipart/alternative; 
	boundary="----=_Part_6897777_1225176489.1439931716939"
Content-Length: 550

------=_Part_6897777_1225176489.1439931716939
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 7bit



------=_Part_6897777_1225176489.1439931716939
Content-Type: text/html; charset=UTF-8
Content-Transfer-Encoding: 7bit

<html><body><div style="color:#000; background-color:#fff; font-family:HelveticaNeue-Light, Helvetica Neue Light, Helvetica Neue, Helvetica, Arial, Lucida Grande, sans-serif;font-size:16px"><div id="yui_3_16_0_1_1439930786516_3733"><br></div></div></body></html>
------=_Part_6897777_1225176489.1439931716939--`, "\n", "\r\n", -1)

func TestYahooIncSignupTo(t *testing.T) {
	email, data, err := CheckEmailProof([]byte(testYahooIncTo), "andreser@mit.edu", "E2ETEST: ", yIncTXT, yIncTime)
	if err != nil {
		t.Error(err)
	}
	if want, got := "andreser@yahoo-inc.com", email; got != want {
		t.Errorf("got %q (wanted %q)", got, want)
	}
	if want, got := "12345", data; got != want {
		t.Errorf("got %q (wanted %q)", got, want)
	}
}

func TestRejectUnknownTo(t *testing.T) {
	email, data, err := CheckEmailProof([]byte(testYahooIncTo), "notpresent@example.com", "E2ETEST: ", yIncTXT, yIncTime)
	if err == nil {
		t.Error("unknown To passed")
	}
	if email != "" {
		t.Error("unknown To returned an email")
	}
	if data != "" {
		t.Error("unknown To returned some data")
	}
}
