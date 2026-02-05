rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specifically targeting known exit decision points with precise conditions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 4D FC EA EE 01 31 5E 83 }
        $pattern1 = { E9 B5 FC FF FF CD EC FC }
        $pattern2 = { E8 BE FE 0A 01 EC FC EE CE EA BA }

    condition:
        any of the patterns match
}