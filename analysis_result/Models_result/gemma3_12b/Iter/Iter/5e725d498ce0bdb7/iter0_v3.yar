rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 41 E2 A3 A9 C5 1E B6 55 ?? } // test eax, 55B61EC5h, manipulate eax
        $pattern1 = { 41 E3 0E 52 8B 16 50 51 FF D2 5E 5D C3 } // call eax, bypass the call
        $pattern2 = { 41 E2 DA EE 79 B4 ?? ?? ?? ?? } // out dx, al, conditional jump

    condition:
        any of them
}