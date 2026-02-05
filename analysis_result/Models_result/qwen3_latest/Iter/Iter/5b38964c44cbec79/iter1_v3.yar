rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 07 50 FF 15 ?? ?? ?? ?? }  // test eax, eax + je + push + call
        $pattern1 = { 55 8B EC 50 E8 ?? ?? ?? ?? }        // push ebp + mov ebp + push + call
        $pattern2 = { A8 01 75 10 FF 15 ?? ?? ?? ?? }     // test al, 01h + jne + call

    condition:
        any of them
}