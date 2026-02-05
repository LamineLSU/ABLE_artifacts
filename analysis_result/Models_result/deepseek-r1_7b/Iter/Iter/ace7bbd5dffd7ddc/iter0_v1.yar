rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting exit functions"
        cape_options = "bp0=$pattern0+0,bp1=$pattern1+0,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 0041E2D6 ?? }  
        $pattern1 = { 0041E2C3 ?? }  
        $pattern2 = { FFD0 ?? }
}

# Each pattern is explained below