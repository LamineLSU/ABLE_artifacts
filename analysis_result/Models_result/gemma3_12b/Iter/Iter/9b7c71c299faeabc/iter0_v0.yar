rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 50 E8 CD D3 01 00 } // push ebx; push eax; call 0x42FEB0
        $pattern1 = { 85 C0 75 3A 50 8D 85 } // test eax; jne; push eax; lea
        $pattern2 = { 55 8B E5 81 EC 0C 01 00 00 } // push ebp; mov ebp, esp; sub esp, 0000010Ch

    condition:
        any of them
}