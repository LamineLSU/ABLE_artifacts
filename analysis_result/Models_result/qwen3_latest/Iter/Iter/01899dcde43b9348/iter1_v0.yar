rule SampleDetection
{
    meta:
        description = "Detects a specific sample based on unique instruction patterns"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "AI"
        date = "2023-10-05"

    strings:
        $a = { 85 C0 74 12 6A 5B 5A 8B CE } // Test/je + register manipulation
        $b = { 85 C0 0F 84 33 FD FF }        // Second test/je pair
        $c = { FF 15 2C A1 D0 00 }           // Call to exit function

    condition:
        all of ($a, $b, $c)
}