use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;

fn ceil_sqrt(x: &BigUint) -> (BigUint, bool)
{
    let mut is_square = true;
    let mut res = x.sqrt();
    if &res.pow(2) < x {
        res = &res + 1u32;
        is_square = false;
    }
    (res, is_square)
}

// if (A^2 - kN) is a square, and x = sqrt(A^2 - kN)
// then p = (A - x)/i and q = (A + x)/j is a factorization
// for N = pq iff k = ij
// Try A = ceil_sqrt(kN) + t for t = 0..max_tries
// Optionally return the factors (p,q) and the number of tries
fn find_factors(modulus: &BigUint,
                max_tries: u32,
                coeffs: Option<(u32, u32)>) -> Option<(BigUint, BigUint, u32)>
{
    let (i, j, k) = match coeffs {
        None => { (1u32, 1u32, 1u32) }
        Some((ci, cj)) => { (ci, cj, ci * cj)}
    };
    let kn = (modulus * k).clone();
    let (mut a, _) = ceil_sqrt(&kn);
    for t in 0..max_tries {
        match ceil_sqrt(&(a.pow(2) - &kn)) {
            (x, true) => {
                let p = (&a - &x) / &i;
                let q = (&a + &x) / &j;
                return Some((p, q, t + 1));
            }
            (_, false) => {
                a = a + 1u32;
            }
        }
    }
    None
}

fn inverse_mod(a: BigUint, modulus: BigUint) -> Option<BigUint>
{
    let elem = BigInt::from_biguint(Sign::Plus, a);
    let m = BigInt::from_biguint(Sign::Plus, modulus);
    let ext = elem.extended_gcd(&m);
    if ext.gcd == BigInt::from(1u8) {
        return Some(BigUint::try_from(ext.x).unwrap());
    }
    None
}

fn challenge(idx: u8,
             modulus: &BigUint,
             max_tries: u32,
             coeffs: Option<(u32, u32)>) -> Option<(BigUint, BigUint)>
{
    match find_factors(&modulus, max_tries, coeffs) {
        None => {
            println!("Couldn't find factors of challenge {} in {} tries", idx, max_tries);
            None
        }
        Some((p, q, tries)) => {
            assert_eq!(modulus, &(&p * &q));
            println!("Factors of challenge {} (tries: {}):\np = {}\nq = {}", idx, tries, p, q);
            Some((p, q))
        }
    }
}

fn main()
{
    // Challenge 1
    // The following modulus N is a products of two primes p and q
    // where |p - q| <= 2 N^{1/4}
    // ==> should be factored in a single try with A = ceil(sqrt(N))
    let modulus1: BigUint = "17976931348623159077293051907890247336179769789423065727343008115\
                            77326758055056206869853794492129829595855013875371640157101398586\
                            47833778606925583497541085196591615128057575940752635007475935288\
                            71082364994994077189561705436114947486504671101510156394068052754\
                            0071584560878577663743040086340742855278549092581".parse().unwrap();
    let max_tries = 1u32;
    // this factorization is used in the last challenge
    let (p, q) = challenge(1, &modulus1, max_tries, None).unwrap();

    // Challenge 2
    // The following modulus N is a products of two primes p and q
    // where |p - q| <= 2^11 N^{1/4}
    // ==> should be factored trying with A_i = ceil(sqrt(N)) + i for i = 0..2^20
    let modulus: BigUint = "6484558428080716696628242653467722787263437207069762630604390703787\
                            9730861808111646271401527606141756919558732184025452065542490671989\
                            2428844841839353281972988531310511738648965962582821502504990264452\
                            1008852816733037111422964210278402893076574586452336833570778346897\
                            15838646088239640236866252211790085787877".parse().unwrap();
    let max_tries = 1 << 20;
    challenge(2, &modulus, max_tries, None);

    // Challenge 3
    // The following modulus N is a products of two primes p and q
    // where |3p - 2q| <= N^{1/4}
    // ==> should be factored in a single try with A = ceil(sqrt(24N))
    let modulus: BigUint = "72006226374735042527956443552558373833808445147399984182665305798191\
                            63556901883377904234086641876639384851752649940178970835240791356868\
                            77441155132015188279331812309091996246361896836573643119174094961348\
                            52463970788523879939683923036467667022162701835329944324119217381272\
                            9276147530748597302192751375739387929".parse().unwrap();
    let max_tries = 1u32;
    challenge(3, &modulus, max_tries, Some((6, 4)));

    // Challenge 4
    // Use the factorization of challenge 1 to decrypt a ciphertext given the public key
    let ct: BigUint = "220964518674103817763065611348834180174100697878928310717318391436761356\
                       001205380042823296504735094243439462197515122564658399679428894607645420\
                       405815647489880137348641204523252293201764879166664029975091887299716905\
                       260832220677716000193292608700095799937240774589677736978175712672299511\
                       48662959627934791540".parse().unwrap();
    let pk: BigUint = "65537".parse().unwrap();

    let phi = (p - 1u32) * (q - 1u32);
    let sk = inverse_mod(pk, phi).unwrap();
    let plaintext = ct.modpow(&sk, &modulus1).to_bytes_be();

    // Check first byte
    assert_eq!(plaintext[0], 0x02);
    // find 0x00 separator and print final text
    let pad = plaintext.iter().position(|&x| x == 0x00).unwrap();
    println!("Challenge 4 Plaintext: {}", String::from_utf8_lossy(&plaintext[(pad + 1)..]));
}
