rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { B9 42 8C 86 00 50 E8 ?? ?? ?? ?? }  // mov ecx, 00868C42h + push + call
        $pattern1 = { 33 C9 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 85 C0 74 ?? }  // xor ecx + call + mov + test + je
        $pattern2 = { FF 75 08 E8 ?? ?? ?? ?? 85 C0 74 ?? }  // push + call + test + je

    condition:
        any of them
}