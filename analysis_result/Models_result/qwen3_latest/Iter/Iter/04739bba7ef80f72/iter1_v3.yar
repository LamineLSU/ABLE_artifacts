rule EvasionCheck
{
    meta:
        description = "Detects evasion checks and exit logic in the sample"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "AI"
        date = "2023-10-15"

    strings:
        $a = { 85 C0 74 0E E8 E0 A2 FF FF } // Test + je + call
        $b = { 85 C0 74 0E E8 B7 F7 FF FF } // Test + je + call
        $c = { FF 15 14 28 43 00 } // ExitProcess call

    condition:
        (uint8($a) or uint8($b) or uint8($c))
}