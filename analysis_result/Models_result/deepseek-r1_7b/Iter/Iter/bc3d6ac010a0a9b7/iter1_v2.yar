rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 5E 8DB0 980C FFD2 ?? }
        $pattern1 = { E8740A0000 ?? }
        $pattern2 = { 6A 5A 8B CE E8 ?? }

    condition:
        any of them
}