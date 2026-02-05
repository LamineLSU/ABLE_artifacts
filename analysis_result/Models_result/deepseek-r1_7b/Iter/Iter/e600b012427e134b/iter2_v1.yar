rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific sequence targeting"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 48 2C CA 6A 48 2E 6A 48 2F 6A 48 31 EA CA 6A 48 36 E0 6A 48 38 }
        $pattern1 = { 6A 48 53 6A 48 54 CA 6A 48 5A 6A 48 5D E0 6A 48 62 }
        $pattern2 = { 6A 48 7D CC 6A 48 81 6A 48 83 6A 48 85 E0 6A 48 87 }

    condition:
        any of them
}