rule Malware_Detection
{
    meta:
        description = "Detects a specific malware pattern involving ExitProcess and other checks"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { FF 75 08 E8 ?? ?? ?? ?? 90 }  // Push [ebp+08h], call (displacement), NOP
        $b = { 83 F8 01 74 20 E8 ?? ?? ?? ?? }  // CMP EAX, 1, JE, call (displacement)
        $c = { C1 E8 08 A8 01 75 10 }  // SHR EAX, 08h, TEST AL, 01h, JNE
    condition:
        any of ($a, $b, $c)
}