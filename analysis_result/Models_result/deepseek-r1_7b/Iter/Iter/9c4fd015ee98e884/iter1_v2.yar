rule Bypass_Sample_Evasion {
    meta:
        description = "Evasion bypass detection rule targeting specific call sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { [83C4] + [85C0] + [8BEC] + [E8] + [??] + [??] + [??] }
        $pattern1 = { [6A] + [??] + [5A] + [8BCE] + [E8] + [??] + [??] + [??] + [??] }
        $pattern2 = { [0F49] + [87D3] + [FF1C] + [00000000] }

    condition:
        any of them
}