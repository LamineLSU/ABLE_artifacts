rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 6A ?? 8B 45 ?? E8 ?? ?? ?? ?? 85 C0 }  //Bypass the call instruction
        $pattern1 = { 8B C7 33 FF 8B C7 EB 03 8B 45 ?? } //Bypass the conditional jump
        $pattern2 = { 8B E5 5D 8B E5 C3 } //Bypass the int3 breakpoint

    condition:
        any of them
}