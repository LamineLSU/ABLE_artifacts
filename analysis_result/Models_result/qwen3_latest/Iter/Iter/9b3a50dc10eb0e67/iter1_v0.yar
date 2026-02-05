rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? }  // Call to evasion logic (TRACE //1/2)
        $pattern1 = { E8 ?? ?? ?? ?? 55 8B EC }  // Call + push ebp + mov ebp (TRACE //3)
        $pattern2 = { E8 ?? ?? ?? ?? 83 F8 01 74 20 }  // Call + cmp eax + je (TRACE //3)

    condition:
        any of them
}