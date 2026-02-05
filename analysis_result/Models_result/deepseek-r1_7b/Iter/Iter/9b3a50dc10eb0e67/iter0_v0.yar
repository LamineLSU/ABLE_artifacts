rule Bypass_Sample {
    meta:
        description = "Evasion bypass using specific call patterns and addresses"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 D1 FF FF FF FF ?? } // Matches the call with displacement from trace //1
        $pattern1 = { FF 15 A8 01 B8 ?? } // Matches a displacement call from trace //3's first instruction
        $pattern2 = { 74 85 C0 E8 ?? ?? } // Matches JZ followed by an E8 call with unknown addresses in trace //3
    condition:
        any_of them
}