rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting specific function calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = "{83F801 7420 FF7508 FF153CF14200}"
        $pattern1 = "{8B04 FF7508 FF153CF14200}"
        $pattern2 = "{E8F72500 FF7508 FF153CF14200}"
}

count=0