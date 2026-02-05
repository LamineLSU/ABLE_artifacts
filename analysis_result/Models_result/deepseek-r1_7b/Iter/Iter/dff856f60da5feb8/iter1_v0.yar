rule Bypass_Sample
{
    meta:
        description = "Evasion bypass targeting specific address calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? FF 50 00 EB }  // From trace //3
        $pattern1 = { E8 ?? FF FA FF FF 40 1B 0A ?? }  // From trace //2
        $pattern2 = { E8 ?? 25 05 00 EC ED ED 8B C3 }  // From trace //1

    condition:
        any of them
}