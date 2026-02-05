rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 DC 35 31 00 3B C7 75 E1 }  // CALL OpenEventA + CMP EAX, EDI + JNZ
        $pattern1 = { FF 15 24 37 31 00 8B F0 74 03 }  // CALL CreateEventA + MOV ESI, EAX + JZ
        $pattern2 = { E8 73 49 FF FF 74 03 }           // CALL to 0x0010190F + JZ

    condition:
        any of them
}