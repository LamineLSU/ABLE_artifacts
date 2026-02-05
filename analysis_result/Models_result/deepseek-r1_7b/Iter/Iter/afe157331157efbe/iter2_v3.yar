rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting call instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C8 FFFFFF 5A 8B CE ?? ?? ?? ?? FF7508 ?? }
        $pattern1 = { FF15AC B04100 5A FF7508 4D 59 ?? ?? ?? ?? FF7508 ?? }
        $pattern2 = { 8B EC 5A 8B CE E8 ??.??.?.??.?.??.?. } 

    condition:
        any of them
}