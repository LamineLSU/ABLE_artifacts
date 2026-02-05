rule Bypass_Evasion {
    meta:
        description = "Evasion bypass patterns targeting call and stack operations"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF7508 E8C8FFFFFF }
        $pattern1 = { E8C8FFFFFF 59 }
        $pattern2 = { 8BEC FF7508 E8C8FFFFFF }
}