rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 85 C0 FB FF FF }  //LEA EAX, dword ptr [ebp-00000440h]
        $pattern1 = { 5F 89 85 D0 FB FF FF } // POP EDI, MOV dword ptr [ebp-00000430h], eax
        $pattern2 = { 8D 75 08 E8 21 B1 FF FF } // LEA esi, dword ptr [ebp+08h], CALL 00417F4E

    condition:
        any of them
}