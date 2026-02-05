rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass by skipping conditional jumps and argument checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 75 EC FF75 ?? ??.8B 45 ?? }
        $pattern1 = { E8C8FFFFF 8B 45 ?? }
        $pattern2 = { FF15ACB04100 }
}