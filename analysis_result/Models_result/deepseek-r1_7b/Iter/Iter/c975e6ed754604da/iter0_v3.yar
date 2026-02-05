rule Bypass_Sample {
    meta:
        description = "Evasion bypass by manipulating displacement checks and adding decoy instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
    
    strings:
        $pattern0 = { 20 E8 C8 FF FF FF 59 FF 75 08 }
        $pattern1 = { 20 E8 C8 FF FF FF FF 75 08 ?? }
        $pattern2 = { 20 E8 C8 FF FF FF 59 FF 75 08 59 FF 75 08 }
    
    condition:
        any() {
            $pattern0
            $pattern1
            $pattern2
        }
}