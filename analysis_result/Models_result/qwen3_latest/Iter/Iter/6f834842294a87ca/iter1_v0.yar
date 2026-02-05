rule Malware_Evasion
{
    meta:
        description = "Detects evasion techniques involving calls to ExitProcess and ___crtCorExitProcess"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Security Analyst"
        date = "2023-10-05"

    strings:
        $a = { 8B FF 55 8B EC FF 75 08 E8 ?? ?? ?? ?? }  // mov edi, edi | push ebp | mov ebp, esp | push [ebp+08h] | call
        $b = { 59 FF 75 08 FF 15 ?? ?? ?? ?? }         // pop ecx | push [ebp+08h] | call
        $c = { 8B FF 55 8B EC FF 75 08 }                // mov edi, edi | push ebp | mov ebp, esp | push [ebp+08h]

    condition:
        all of ($a $b $c)
}