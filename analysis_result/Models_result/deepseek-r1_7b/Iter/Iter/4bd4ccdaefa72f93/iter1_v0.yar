rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific trace points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 488D536C E8 ?? ?? ?? ?? }
        $pattern1 = { 00007FF72BA510F0 4889742460 74 ?? ???? ?? }
        $pattern2 = { FF15E90E C7442420 74 ?? ???? ?? }

    condition:
        any of them
}