rule EvasionChecks
{
    meta:
        description = "Detects evasion checks via test/jump sequences and API calls"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Security Analyst"
        date = "2023-10-05"

    strings:
        $a = { 85 C0 74 12 6A 5B } // Test + short jump + push
        $b = { 85 C0 0F 84 ?? ?? ?? ?? } // Test + relative jump (offset wildcard)
        $c = { FF 15 2C A1 0A 01 } // Direct API call to ExitProcess

    condition:
        any of ($a, $b, $c)
}