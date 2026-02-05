rule Bypass_Evasion {
    meta:
        description = "Bypasses calls made during the execution of E8C8FFFFFF"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C8 FF FF }
        $pattern1 = { 75 FF FF FF } // Represents the offset after another call
        $pattern2 = { E8 C4 FF FF } // Another call with similar structure

    condition:
        any_of them
}