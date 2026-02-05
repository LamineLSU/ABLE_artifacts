rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting multiple detection points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8BEC FF7508 E8C1???F 59 FF7508 FF155CC24C00 }  
        $pattern1 = { 55 8BEC FF7508 E8C1???F 59 FF7508 0F 45 FF C0 }
        $pattern2 = { 55 8BEC FF7508 E8C1???F 5A 8B CE E8 FF ???F }

    condition:
        any of them
}