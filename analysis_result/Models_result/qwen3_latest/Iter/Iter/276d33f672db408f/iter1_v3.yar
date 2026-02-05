rule ExampleRule {
    meta:
        description = "Example rule with specific byte patterns"
    strings:
        $a = { 78 12 0C 00 0C 00 }  // js followed by two or instructions
        $b = { E8 44 09 00 00 00 56 50 }  // call instruction and subsequent add
        $c = { 00 56 50 56 50 E8 44 09 00 00 }  // add, push, and call sequence
    condition:
        all of them
}