package https

/*
** EFF's Http-everywhere:
** This source contains exports for both _server_ and client-side use, as in, the construction of the ruleset in proprietary format
**   and the reconstruction into memory, and actual intended URL rewrite logic
** The general approach is to teach a filter about the simple target hosts (no wildcard, or one wildcard at one of the endings of the pattern),
**   this will block the vast majority of sites (with testing time well below the millisecond), complicated wildcards will be saved in a map,
**   and transformed into a pcre regex pattern (the * token will be expanded into [^\.]+) and precompiled for speed (right now there are 22 such cases),
**   and tried by matching the input versus the compiled regex; lastly there's a hashmap (which has indices the 32bit hash of the target string representation,
**	 values, the associated rulesets) which will load the available rules to apply, this is a filtering and retrieval logic.
**   Upon generating the structure hash collisions are handled by evacuating the colliding entry into the forward structure.
**   A flow of rewrite is as follows:
**     1. try to match input to forward map regexes
**     1.1 if match occurs, apply the first rule that fits (return if url is excluded), return the resulting url
**     2. try url in filter, if is not found (not, there is 0% false negatives) return
**     3. find the asociated rulesets with combinations {url, url_first_subdomain_wildcarded, url_tld_wildcarded}
**     (Example: input = somesubdomain.example.com -> {somesubdomain.example.com, *.example.com, somesubdomain.example.*})
**     3.1 if there's a match, apply the first rule that fits (return if url is excluded), and return the new url
** Encoding takes the structures and serializes them in a space optimized format, cuckoofilter has already an encode implemented, slice is encoded in a straightforward manner,
**   regularMap (aka map[uint32][]int, aka hash(url)->array(of_applicable_rulesets)) needs an extra step, since the unique values are around 5K (the `int`s from all the `[]int`s),
**   the implementation is to flip the map and try to encode a [][]uint32
**   where the index of the first dimension is the value from the map, and the second index is the order of occurence of the hash, and finally the uint32 values are the hashes
** Exported functions:
**   Parse -- reads the rules from the given path, and constructs the appropriate structures resulting in a HtEvSt or an error
**   Encode/EncodeToPath/Decode -- as their name suggests handles encoding and decoding of the structure, EncodeToPath flushes the compressed format to a specified file.
**   TryRewrite -- searches for and applies the appropriate rewrite rules, returns the new url (or old one if no match occured) or an error
 */
import (
	"bytes"
	"dawgutils/serialize"
	"encoding/xml"
	"fmt"
	"hash/fnv"
	"io/ioutil"
	"math"
	"strings"
	"time"

	"github.com/seiflotfy/cuckoofilter"
	"github.com/tenta-browser/goutils"
	"golang.org/x/net/publicsuffix"
)

/// cannot const the slice
var possibleUintDelimiter = map[uint32]bool{0xfadea3a1: true, 0xbaadface: true, 0xfefefefe: true, 0x0dabbee2: true, 0xffffffff: true}
var chosenDelimiter uint32
var encodeBits = 16
var encodeMap map[int]int

type RuleSt struct {
	From string `xml:"from,attr"`
	To   string `xml:"to,attr"`
}

type TargetSt struct {
	Host string `xml:"host,attr"`
}

type ExclusionSt struct {
	Pattern string `xml:"pattern,attr"`
}

type TestSt struct {
	Url string `xml:"url,attr"`
}

type RulesetSt struct {
	Index     int
	Name      string        `xml:"name,attr"`
	Disabled  string        `xml:"default_off,attr"`
	Target    []TargetSt    `xml:"target"`
	Rule      []RuleSt      `xml:"rule"`
	Exclusion []ExclusionSt `xml:"exclusion"`
	Test      []TestSt      `xml:"test"`
}

type SimplifiedRulesetSt struct {
	exclusion, ruleFrom, ruleTo []string
}

type HtEvSt struct {
	filterBytesNum, forwardBytesNum int
	input                           []*RulesetSt
	filter                          *cuckoofilter.CuckooFilter
	forward                         map[string][]*RulesetSt
	// reconstructedForward            map[string]int /// this will be the decoded version of forward, int is an index in regularSlice
	optimizedForward map[goutils.Regexp][]int
	regularMap       map[uint32][]int
	regularSlice     []*SimplifiedRulesetSt
}

var RuleIndex int = 0

func tokenizeURL(in string) (scheme, domain, site string, subdomain []string, e error) {
	/// detach the scheme part

	if strings.HasPrefix(in, "http://") {
		scheme = "http"
		in = in[7:]
	} else {
		e = fmt.Errorf("protocol is not supported")
		return
	}
	/// now detach the site part, or rather anything, that comes after the `/' token
	si := strings.Index(in, "/")
	if si > -1 {
		site = in[si+1:]
		in = in[:si]
	}

	domain, e = publicsuffix.EffectiveTLDPlusOne(in)
	if e != nil {
		e = fmt.Errorf("publicsuffix error [%s]", e.Error())
		return
	}

	si = strings.Index(in, domain)
	if si > 0 {
		subdomain = strings.Split(in[:si-1], ".")
	}

	return
}

/// search for the linked rule structure in the standard fashion: forward map, by regex, filter and regular map
func (h *HtEvSt) search(t string) (ruleInd []int, e error) {

	_, domain, _, subdomain, e := tokenizeURL(t)
	if e != nil {
		return nil, fmt.Errorf("cannot tokenize [%s]", e.Error())
	}
	// fmt.Printf("Launched search for [%s] -> we have [%s] [%v]\n", t, domain, subdomain)

	orig := append(subdomain, strings.Split(domain, ".")...)
	// fmt.Printf("Orig is [%v]\n", orig)
	origLen := len(orig)
	variations := []string{strings.Join(orig, "."), strings.Join(append(orig[:origLen-1], "*"), ".")}
	/// wildcard subdomains only if they exist in the url
	if subdomain != nil {
		variations = append(variations, strings.Join(append([]string{"*"}, variations[0]), "."), strings.Join(append([]string{"*"}, orig[1:]...), "."))
	}
	/// first check forward, will do so once pcre support is established
	/// forward now has keys as regexes, so we'll compile and try to apply them (will do a precompile pass later, in the decode phase)

	for k, v := range h.optimizedForward {
		// r := goutils.ReEngine.Compile(k, 0)
		// if e != nil {
		// 	return nil, fmt.Errorf("error compiling [%s], [%s]", k, e.Error())
		// }
		// fmt.Printf("Matching [%s] vs [%s] --> [%v]\n", variations[0], k, r.Search(variations[0]).GroupPresentByIdx(0))
		/// we have a match for the whole pattern
		if m := k.Search(variations[0]); m != nil && m.GroupPresentByIdx(0) == true {
			fmt.Printf("Rule struct found via forward.\n")
			// return v, nil
			if ruleInd == nil {
				ruleInd = make([]int, 0)
			}
			ruleInd = append(ruleInd, v...)
		}
	}
	fmt.Printf("Searching using [%v]\n", variations)
	/// next, check filter and map
	for _, v := range variations {
		if h.filter.Lookup([]byte(v)) {
			if ind, contains := h.regularMap[hash(v)]; contains {
				fmt.Printf("Rule struct found via filter+regular.\n")
				//return ind, nil
				if ruleInd == nil {
					ruleInd = make([]int, 0)
				}
				ruleInd = append(ruleInd, ind...)

			}
		}
	}

	return ruleInd, nil
}

/// exported function which finds rule struct (if applicable), and applies the (most) appropriate rewrite rule
/// okay, so, tri-state return: problem -> e != nil, no match -> out == "" && e == nil, match -> out != "" && e != nil
func (h *HtEvSt) TryRewrite(in string) (out string, e error) {
	out = in
	start := time.Now()
	ruleIndices, e := h.search(in)
	if e != nil {
		return "", fmt.Errorf("search error [%s]", e.Error())
	}
	if ruleIndices == nil {
		return
	}
	fmt.Printf("Search yielded for [%s] %d rule sets\n", in, len(ruleIndices))

	/// here comes another batch of pcre-dependent codes
	for _, ri := range ruleIndices {
		//fmt.Printf("Trying rule index [%d] of [%d]\n", i, len(ruleIndices))
		rule := h.regularSlice[ri]
		needsToContinue := false
		for _, excl := range rule.exclusion {
			re, e := goutils.ReEngine.Compile(excl, 0)
			if e != nil {
				return "", fmt.Errorf("cannot compile exclusion [%s]", e.Error())
			}
			/// try matching the exclusions
			if m := re.Search(in); m != nil && m.GroupPresentByIdx(0) == true {
				fmt.Printf("Input [%s] excluded via pattern [%s].\n", in, excl)
				//return "", nil
				needsToContinue = true
				break
			}
		}
		if needsToContinue {
			continue
		}
		/// by getting this far, means we have to find a rule for our input (if not, it's a https-everywhere rule collection miss (theoretically, at least))
		for i, rewrite := range rule.ruleFrom {
			re, e := goutils.ReEngine.Compile(rewrite, 0)
			if e != nil {
				return "", fmt.Errorf("cannot compile rewrite [%s]", e.Error())
			}

			if m := re.Search(in); m != nil && m.GroupPresentByIdx(0) == true {
				fmt.Printf("Input [%s] matching rewrite pattern [%s].\n", in, rewrite)
				//out := re.ReplaceAllString(in, rule.ruleTo[i], 0)
				out := re.Replace(in, rule.ruleTo[i])
				fmt.Printf("Rewrote to [%s]\n", out)
				fmt.Printf("Search+Rewrite took [%v] time.\n", time.Now().Sub(start))
				return out, nil
			}
		}
	}
	///in a first run let's handle as non-error the case when no rewrite rule could be found (but targets match)
	return "", nil
}

func (h *HtEvSt) NewRulesetSt() (r *RulesetSt) {
	r = &RulesetSt{Index: RuleIndex}
	RuleIndex++
	h.input = append(h.input, r)
	if len(h.input) != RuleIndex {
		panic(fmt.Sprintf("index mismatch"))
	}
	return
}

func NewSimplifiedRulesetSt() *SimplifiedRulesetSt {
	//return &SimplifiedRulesetSt{make([]string, 0), make([]string, 0), make([]string, 0)}
	return &SimplifiedRulesetSt{}
}

/// decodes forward map into reconstructedForward; does not contain byte length uint32
func decodeForwardMap(b []byte) (m map[goutils.Regexp][]int, e error) {
	r := serialize.NewBitStreamOpsReader(b)
	m = make(map[goutils.Regexp][]int)
	var temp uint
	var temps string
	/// straight _forward_ loop
	for r.HasMoreBytes() {
		if temp, e = r.Collect(32); e != nil {
			return nil, fmt.Errorf("error collecting str length [%s]", e.Error())
		}
		if temps, e = r.DeConcat(int(temp)); e != nil {
			return nil, fmt.Errorf("error collecting string [%s]", e.Error())
		}
		if temp, e = r.Collect(32); e != nil {
			return nil, fmt.Errorf("error collecting slice index [%s]", e.Error())
		}
		/// to be able to look them up using regex (does not exactly validate for valid domain composition)
		re, e := goutils.ReEngine.Compile(strings.Replace(temps, "*", "[\\w-]+", -1), 0)
		if e != nil {
			return nil, fmt.Errorf("cannot compile wildcard domain in forward map")
		}
		if m[re] == nil {
			m[re] = make([]int, 0)
		}
		m[re] = append(m[re], int(temp))
	}

	return
}

/// encodes forward map (a formality really, since around 20 entries here), references indices from regularSlice
/// byte length will be added further up in the callstack
func encodeForwardMap(h *HtEvSt) (ret []byte, e error) {
	b := serialize.NewBitStreamOps()
	/// no need to add length param here as it does not speedup decode
	/// basic scheme: ([strlen][str][index]){len(h.forward)}
	for target, ruleArr := range h.forward {
		for _, rule := range ruleArr {
			//fmt.Printf("[%s] =>\n[%s]\nvs\n[%s]\n", target, rule, h.regularSlice[encodeMap[rule.Index]])
			if e = b.Emit(uint(len(target)), 32); e != nil {
				return nil, fmt.Errorf("error emitting str length [%s]", e.Error())
			}
			b.Concat(target)
			if e = b.Emit(uint(encodeMap[rule.Index]), 32); e != nil {
				return nil, fmt.Errorf("error emitting index [%s]", e.Error())
			}
		}
	}
	return b.Buffer(), nil
}

/// some of these functions are wrappers
/// does not include byte slice length uint
func decodeRegularSlice(b []byte) ([]*SimplifiedRulesetSt, error) {
	r := serialize.NewBitStreamOpsReader(b)
	var sliceLen, elemLen uint
	var elem []byte
	var e error
	if sliceLen, e = r.Collect(32); e != nil {
		return nil, fmt.Errorf("decodeRegularSlice error [%s]", e.Error())
	}
	// fmt.Printf("Slice elem num is [%d]\n", sliceLen)
	ret := make([]*SimplifiedRulesetSt, int(sliceLen))
	for i := 0; i < int(sliceLen); i++ {
		// fmt.Printf("[%d]", i)
		if elemLen, e = r.Collect(32); e != nil {
			return nil, fmt.Errorf("decodeRegularSlice elem size error [%s]", e.Error())
		}
		// fmt.Printf("Next elem is [%d] bytes long.\n", elemLen)
		if elem, e = r.DeAppend(int(elemLen)); e != nil {
			return nil, fmt.Errorf("decodeRegularSlice elem error [%s]", e.Error())
		}
		ret[i] = NewSimplifiedRulesetSt()
		if e = ret[i].decode(elem); e != nil {
			return nil, e
		}
	}

	return ret, e
}

/// does not include whole encoding length (part of why it's delegated to a function)
func encodeRegularSlice(r []*SimplifiedRulesetSt) (ret []byte, e error) {
	b := serialize.NewBitStreamOps()
	b.Emit(uint(len(r)), 32)
	// fmt.Printf("Regular slice elem num is [%d]\n", len(r))
	// fmt.Printf("And that looks like this [%x]\n", b.Buffer()[len(b.Buffer())-4:])
	for _, sr := range r {
		t := sr.encode()
		b.Append(t)
	}
	ret = b.Buffer()
	return
}

/// decoding of the regular map. (iterative construction)
func decodeRegularMap(b []byte) (m map[uint32][]int, e error) {
	/// byte slice comes without the length declaration (it's used further up in the stack)
	r := serialize.NewBitStreamOpsReader(b)
	m = make(map[uint32][]int)
	var delimiter, temp uint

	if delimiter, e = r.Collect(32); e != nil {
		return nil, fmt.Errorf("cannot collect delimiter for regular map [%s]", e.Error())
	}

	runningIndex := 0
	for r.HasMoreBytes() {
		if temp, e = r.Collect(32); e != nil {
			return nil, fmt.Errorf("cannot collect temp value for regular map [%s]", e.Error())
		}

		/// check if we need to increment `index`
		if temp == delimiter {
			runningIndex++
		} else { /// or we can save temp as key
			if m[uint32(temp)] == nil {
				m[uint32(temp)] = make([]int, 0)
			}
			m[uint32(temp)] = append(m[uint32(temp)], runningIndex)
		}
	}

	// fmt.Printf("Reconstructed regular map. it has dimension of [%d]\n", len(m))
	return
}

/// encoding of the regular map. this one is tricky, for in-depth process and design choices, consult paragraph from beginning of file
func encodeRegularMap(h *HtEvSt) (ret []byte, e error) {
	b := serialize.NewBitStreamOps()
	/// gets the number of possible indices in the map (the values)
	numIndices := len(h.regularSlice)
	/// allocate a temporary triaging slice, for inverting the map (key-value-wise)
	temp := make([][]uint32, numIndices)
	/// k is the 32bit hash of the target, v is the index in the regularSlice
	for k, vArr := range h.regularMap {
		for _, v := range vArr {
			/// also check for the delimiter
			if _, contains := possibleUintDelimiter[k]; contains {
				possibleUintDelimiter[k] = false
				hasAtLeastOne := false
				for _, validDelimiter := range possibleUintDelimiter {
					if validDelimiter {
						hasAtLeastOne = true
						break
					}
				}
				if !hasAtLeastOne {
					panic("Exhausted delimiter options.\n")
				}
			}

			if temp[v] == nil {
				temp[v] = make([]uint32, 0)
			}
			temp[v] = append(temp[v], k)
		}
	}
	/// let's settle on the delimiter
	var delimiter uint32
	for del, valid := range possibleUintDelimiter {
		if valid {
			delimiter = del
		}
	}
	/// okay, now we can finally encode the flipped map
	/// we write the delimiter (as length will be written up in the stack)
	if e = b.Emit(uint(delimiter), 32); e != nil {
		return nil, fmt.Errorf("cannot emit delimiter for regular map [%s]", e.Error())
	}
	/// now iterate over the temp slice
	for i, uints := range temp {
		/// emitting each hash value referring to this index
		for _, anuint := range uints {
			if e = b.Emit(uint(anuint), 32); e != nil {
				return nil, fmt.Errorf("cannot emit uint32 value regular map [%s]", e.Error())
			}
		}
		/// emitting index incrementing delimiter
		if e = b.Emit(uint(delimiter), 32); e != nil {
			return nil, fmt.Errorf("cannot emit delimiter for regular map [%d/%d] [%s]", i, len(temp), e.Error())
		}
	}
	return b.Buffer(), e
}

/// input byte slice without the leading uint
func (s *SimplifiedRulesetSt) decode(b []byte) error {
	if s.exclusion != nil || s.ruleFrom != nil || s.ruleTo != nil {
		return fmt.Errorf("not a blank structure")
	}
	// fmt.Printf("Called decode with [%d] bytes.<%v>\n", len(b), b)
	var exclSize, fromtoSize, currStrlen uint
	var e error
	r := serialize.NewBitStreamOpsReader(b)
	if exclSize, e = r.Collect(encodeBits); e != nil {
		return fmt.Errorf("decode error [%s]", e.Error())
	}
	// fmt.Printf("Excl size is [%d]\n", exclSize)
	s.exclusion = make([]string, exclSize)
	for i := 0; i < int(exclSize); i++ {
		if currStrlen, e = r.Collect(encodeBits); e != nil {
			return fmt.Errorf("decode error [%s]", e.Error())
		}
		if s.exclusion[i], e = r.DeConcat(int(currStrlen)); e != nil {
			return fmt.Errorf("deconcat error [%s]", e.Error())
		}
	}
	if fromtoSize, e = r.Collect(encodeBits); e != nil {
		return fmt.Errorf("decode error [%s]", e.Error())
	}
	s.ruleFrom = make([]string, fromtoSize)
	s.ruleTo = make([]string, fromtoSize)
	for i := 0; i < int(fromtoSize); i++ {
		if currStrlen, e = r.Collect(encodeBits); e != nil {
			return fmt.Errorf("decode error [%s]", e.Error())
		}

		if s.ruleFrom[i], e = r.DeConcat(int(currStrlen)); e != nil {
			return fmt.Errorf("deconcat error [%s]", e.Error())
		}
		if currStrlen, e = r.Collect(encodeBits); e != nil {
			return fmt.Errorf("decode error [%s]", e.Error())
		}

		if s.ruleTo[i], e = r.DeConcat(int(currStrlen)); e != nil {
			return fmt.Errorf("deconcat error [%s]", e.Error())
		}
	}
	// fmt.Printf("Have :: [%s]\n", s)
	return nil
}

/// emits an uint at the end which declares the byte slice length
func (s *SimplifiedRulesetSt) encode() []byte {
	b := serialize.NewBitStreamOps()
	/// without this here uint32
	overallByteNum := (encodeBits/8)*(len(s.exclusion)+2*len(s.ruleFrom)+2) + s.countChars()
	b.Emit(uint(overallByteNum), 32)
	b.Emit(uint(len(s.exclusion)), encodeBits)
	for _, e := range s.exclusion {
		b.Emit(uint(len(e)), encodeBits)
		if len(e) > int(math.Pow(2, float64(encodeBits))-1) {
			panic(fmt.Sprintf("Size limitation exceeded. [excl] [%d][%s]\n", len(e), e))
		}
		b.Concat(e)
	}

	b.Emit(uint(len(s.ruleFrom)), encodeBits)
	for i, e := range s.ruleFrom {
		b.Emit(uint(len(e)), encodeBits)
		b.Concat(e)
		if len(e) > int(math.Pow(2, float64(encodeBits))-1) {
			panic(fmt.Sprintf("Size limitation exceeded. [from] [%d][%s]\n", len(e), e))
		}
		b.Emit(uint(len(s.ruleTo[i])), encodeBits)
		b.Concat(s.ruleTo[i])
		if len(e) > int(math.Pow(2, float64(encodeBits))-1) {
			panic(fmt.Sprintf("Size limitation exceeded. [to] [%d][%s]\n", len(e), e))
		}

	}
	return b.Buffer()
}

/// shortcut to check for the most common rule
func (s *SimplifiedRulesetSt) isDefaultRule() bool {
	if len(s.exclusion) == 0 && len(s.ruleFrom) == 1 && len(s.ruleTo) == 1 && s.ruleFrom[0] == "^http:" && s.ruleTo[0] == "https:" {
		return true
	}
	return false
}

func (s *SimplifiedRulesetSt) countChars() (n int) {
	a := [][]string{s.exclusion, s.ruleFrom, s.ruleTo}
	for _, z := range a {
		for _, str := range z {
			n += len(str)
		}
	}
	return
}

func (s *SimplifiedRulesetSt) String() (z string) {
	z += fmt.Sprintf("E:")
	for _, e := range s.exclusion {
		z += fmt.Sprintf("[%s]", e)
	}
	z += fmt.Sprintf("  P:")
	for i, e := range s.ruleFrom {
		z += fmt.Sprintf("[%s->%s]", e, s.ruleTo[i])
	}
	return
}

func (r *RulesetSt) String() (s string) {
	s = fmt.Sprintf("\tName [%s]\n", r.Name)
	s += fmt.Sprintf("\tTargets: ")
	for _, e := range r.Target {
		s += fmt.Sprintf("[%s]", e.Host)
	}
	s += fmt.Sprintf("\n")
	s += fmt.Sprintf("\tExclusions: ")
	for _, e := range r.Exclusion {
		s += fmt.Sprintf("[%s]", e.Pattern)
	}
	s += fmt.Sprintf("\n")
	s += fmt.Sprintf("\tRules: ")
	for _, e := range r.Rule {
		s += fmt.Sprintf("[%s->%s]", e.From, e.To)
	}
	s += fmt.Sprintf("\n")
	return
}

func (r *RulesetSt) countChars() (n int) {
	for _, e := range r.Exclusion {
		n += len(e.Pattern)
	}
	for _, e := range r.Target {
		n += len(e.Host)
	}
	for _, e := range r.Rule {
		n += len(e.From) + len(e.To)
	}
	return
}

func (r *RulesetSt) simplify() (s *SimplifiedRulesetSt) {
	s = &SimplifiedRulesetSt{make([]string, 0), make([]string, 0), make([]string, 0)}

	for _, e := range r.Exclusion {
		s.exclusion = append(s.exclusion, e.Pattern)
	}
	for _, rl := range r.Rule {
		s.ruleFrom = append(s.ruleFrom, rl.From)
		s.ruleTo = append(s.ruleTo, rl.To)
	}

	return
}

func (h *HtEvSt) ShowStats() {
	var cnt int
	for _, r := range h.regularSlice {
		cnt += r.countChars()
	}
	fmt.Printf("We have filter [%d], slice [%d], map [%d], forward [%d]. Chars [%d]\n", h.filter.Count(), len(h.regularSlice), len(h.regularMap), len(h.optimizedForward), cnt)
}

func Decode(b []byte) (h *HtEvSt, e error) {
	r := serialize.NewBitStreamOpsReader(b)
	h = &HtEvSt{}
	var temp uint
	var tempb []byte
	remaining := len(b)
	/// read length of filter bytes
	if temp, e = r.Collect(32); e != nil {
		return nil, fmt.Errorf("Cannot read length of filter [%s]", e.Error())
	}
	remaining -= int(temp) + 4
	fmt.Printf("Detaching %d bytes for filter data -- remains %d\n", int(temp), remaining)
	/// detach (yeah, that's what this function should be called) encoded filter bytes
	if tempb, e = r.DeAppend(int(temp)); e != nil {
		return nil, fmt.Errorf("Cannot read filter bytes [%s]", e.Error())
	}
	/// decode filter
	if h.filter, e = cuckoofilter.Decode(tempb); e != nil {
		return nil, fmt.Errorf("Cannot decode filter [%s]", e.Error())
	}
	/// read length of regular slice bytes
	// fmt.Printf("And that looks like this [%x]\n", r.Buffer()[r.Index():r.Index()+8])
	if temp, e = r.Collect(32); e != nil {
		return nil, fmt.Errorf("Cannot read length of regular slice [%s]", e.Error())
	}
	/// detach encoded regular slice bytes
	remaining -= int(temp) + 4
	fmt.Printf("Detaching %d bytes for reg slice data -- remains %d\n", int(temp), remaining)
	if tempb, e = r.DeAppend(int(temp)); e != nil {
		return nil, fmt.Errorf("Cannot read regular slice bytes [%s]", e.Error())
	}
	/// decode regular slice
	if h.regularSlice, e = decodeRegularSlice(tempb); e != nil {
		return nil, fmt.Errorf("Cannot decode regular slice [%s]", e.Error())
	}
	/// read length of regular map bytes
	if temp, e = r.Collect(32); e != nil {
		return nil, fmt.Errorf("Cannot read length of regular map [%s]", e.Error())
	}
	/// detach encoded regular map bytes
	remaining -= int(temp) + 4
	fmt.Printf("Detaching %d bytes for reg map data -- remains %d\n", int(temp), remaining)
	if tempb, e = r.DeAppend(int(temp)); e != nil {
		return nil, fmt.Errorf("Cannot read regular map bytes [%s]", e.Error())
	}
	/// decode regular map
	if h.regularMap, e = decodeRegularMap(tempb); e != nil {
		return nil, fmt.Errorf("Cannot decode regular map [%s]", e.Error())
	}
	/// read length of forward map bytes
	if temp, e = r.Collect(32); e != nil {
		return nil, fmt.Errorf("Cannot read length of forward map [%s]", e.Error())
	}
	remaining -= int(temp) + 4
	fmt.Printf("Detaching %d bytes for fwd map data -- remains %d\n", int(temp), remaining)
	/// detach encoded forward map bytes
	if tempb, e = r.DeAppend(int(temp)); e != nil {
		return nil, fmt.Errorf("Cannot read forward map bytes [%s]", e.Error())
	}
	/// decode forward map
	if h.optimizedForward, e = decodeForwardMap(tempb); e != nil {
		return nil, fmt.Errorf("Cannot decode forward map [%s]", e.Error())
	}

	return
}

func (h *HtEvSt) EncodeToPath(outFile string) (b []byte, e error) {
	b, e = h.Encode()
	if e != nil {
		return nil, e
	}
	bb := new(bytes.Buffer)
	bb.Write(b)
	ioutil.WriteFile(outFile, b, 0755)
	return b, e
}

func (h *HtEvSt) Encode() (ret []byte, e error) {
	e = nil
	var t []byte
	sumBytes := 0
	b := serialize.NewBitStreamOps()
	/// first encode the filter (with leading numbytes)
	t = h.filter.Encode()
	// fmt.Printf("Emitting filter length [%d][%x]\n", len(t), len(t))
	b.Emit(uint(len(t)), 32)
	// fmt.Printf("[%v]\n", b.Buffer())
	b.Append(t)
	sumBytes += len(t) + 4
	// fmt.Printf("Asserting that %d == %d\n", len(b.Buffer()), sumBytes)
	/// next encode the regular slice (with leading numbytes)
	if t, e = encodeRegularSlice(h.regularSlice); e != nil {
		return nil, fmt.Errorf("encode regular slice error [%s]", e.Error())
	}
	// fmt.Printf("Emitting reg slice length [%d][%x]\n", len(t), len(t))
	b.Emit(uint(len(t)), 32)
	// fmt.Printf("And that looks like this [%x]\n", b.Buffer()[len(b.Buffer())-5:])
	b.Append(t)
	// fmt.Printf("And that looks like this [%x]\n", b.Buffer()[sumBytes:sumBytes+4])
	sumBytes += len(t) + 4
	// fmt.Printf("Asserting that %d == %d\n", len(b.Buffer()), sumBytes)
	/// follows encoding of regular map
	if t, e = encodeRegularMap(h); e != nil {
		return nil, fmt.Errorf("encode regular map error [%s]", e.Error())
	}
	b.Emit(uint(len(t)), 32)
	b.Append(t)
	// fmt.Printf("Emitting reg map length [%d][%x]\n", len(t), len(t))
	sumBytes += len(t)
	// fmt.Printf("Asserting that %d == %d\n", len(b.Buffer()), sumBytes)
	/// follows encoding of forward map
	if t, e = encodeForwardMap(h); e != nil {
		return nil, fmt.Errorf("encode forward map error [%s]", e.Error())
	}
	// fmt.Printf("Emitting fwd map length [%d][%x]\n", len(t), len(t))

	b.Emit(uint(len(t)), 32)
	b.Append(t)
	sumBytes += len(t) + 4
	// fmt.Printf("Asserting that %d == %d\n", len(b.Buffer()), sumBytes)

	fmt.Printf("The encode buffer is [%d] bytes long.\n", len(b.Buffer()))

	return b.Buffer(), nil
}

/// calculate the hash of the target (used in encoding)
/// uses 64bit hash, because 32bit has 1 collision
/// le: could move the one collsion to forward table, and save some space at encoding...
func hash(s string) uint32 {
	h := fnv.New32()
	h.Write([]byte(s))
	return h.Sum32()
}

/// when a scattered target is found which already has an entry in the map, a reatroactive rule comassing and entry rewrite is necessary
/// and since the ulterior simplification of rulesets will be made from the input slice, we allocate the new super-rules there
func (r *RulesetSt) retroactiveJoin(s *RulesetSt, hm map[string]*RulesetSt, data *HtEvSt) {
	uniqRules := make(map[string]RuleSt)
	uniqTargets := make(map[string]TargetSt)
	uniqExclusions := make(map[string]ExclusionSt)
	a := []*RulesetSt{r, s}
	/// join slices
	for _, ruleset := range a {
		for _, t := range ruleset.Target {
			uniqTargets[t.Host] = t
		}
		for _, r := range ruleset.Rule {
			uniqRules[r.From+"THIS!!!IS@@@JUST###A$$$TEXT"+r.To] = r
		}
		for _, e := range ruleset.Exclusion {
			uniqExclusions[e.Pattern] = e
		}
	}

	//superRuleset := &RulesetSt{Name: r.Name + "-REDUX", Disabled: r.Disabled, Target: make([]TargetSt, 0), Rule: make([]RuleSt, 0), Exclusion: make([]ExclusionSt, 0)}
	superRuleset := data.NewRulesetSt()
	superRuleset.Name = r.Name + "-REDUX"
	superRuleset.Disabled = r.Disabled
	superRuleset.Target = make([]TargetSt, 0)
	superRuleset.Rule = make([]RuleSt, 0)
	superRuleset.Exclusion = make([]ExclusionSt, 0)

	for _, t := range uniqTargets {
		superRuleset.Target = append(superRuleset.Target, t)
	}
	for _, r := range uniqRules {
		superRuleset.Rule = append(superRuleset.Rule, r)
	}
	for _, e := range uniqExclusions {
		superRuleset.Exclusion = append(superRuleset.Exclusion, e)
	}

	/// at this point we have a brand new combined power-rangers-like super rule. yay.
	/// follows rewriting the map for all entries

	for _, t := range superRuleset.Target {
		// if _, contains := hm[t.Host]; contains {
		//fmt.Printf(">>>Rewriting [%s] with new super-rule.\n", t.Host)
		hm[t.Host] = superRuleset
		// }
	}
	/// propagate the change back to the origin; this helps in persisting the change back to forward table (if applies).
	*r = *superRuleset
}

func Parse(RulePath string) (*HtEvSt, error) {
	list, err := ioutil.ReadDir(RulePath)
	if err != nil {
		return nil, fmt.Errorf("error reading dir. [%s]", err.Error())
	}

	data := new(HtEvSt)
	data.input = make([]*RulesetSt, 0)
	data.filter = cuckoofilter.NewDefaultCuckooFilter()
	data.forward = make(map[string][]*RulesetSt)
	data.regularMap = make(map[uint32][]int)
	data.regularSlice = make([]*SimplifiedRulesetSt, 0)
	inputNum := 0
	regularNum := 0
	inputStrlen := 0
	trickyNum := 0

	test := make(map[string][]*RulesetSt)

	for _, entry := range list {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".xml") {
			continue

		}

		xmldata, err := ioutil.ReadFile(RulePath + "/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("error reading file. [%s]", entry.Name())

		}

		//res := &RulesetSt{}
		res := data.NewRulesetSt()
		if err := xml.Unmarshal(xmldata, &res); err != nil {
			fmt.Printf("Error occured in file [%s] :: [%s]\n", entry.Name(), err.Error())
			continue
		}

		/// use only valid rulesets
		if res.Disabled == "" {
			//data.input = append(data.input, res)
			/// collect some data to brag about
			inputNum += len(res.Target)
			for _, rule := range res.Rule {
				inputStrlen += len(rule.From) + len(rule.To)
			}
			for _, excl := range res.Exclusion {
				inputStrlen += len(excl.Pattern)
			}
			for _, t := range res.Target {
				inputStrlen += len(t.Host)
				/// move support for tricky wildcards to a future time, fortunately the number of these edge cases is 0
				if strings.Contains(t.Host, "*.*") {
					trickyNum++
					continue
				}
				/// when a wildcard is not on one of the extremes of the string, save it in a straightforward map
				if strings.Count(t.Host, "*") >= 1 && !strings.HasPrefix(t.Host, "*") && !strings.HasSuffix(t.Host, "*") {
					fmt.Printf(">>[%s] SAVED IN FORWARD\n", t.Host)
					if data.forward[t.Host] == nil {
						data.forward[t.Host] = make([]*RulesetSt, 0)
					}
					data.forward[t.Host] = append(data.forward[t.Host], res)
					continue
				}
				/// if the pattern is not spectacular in any way, save it in the filter
				data.filter.InsertUnique([]byte(t.Host))
				regularNum++
				/// check for target already in map, and do the grand unification scheme if so
				/// iced the unification scheme, it breaks some rules
				// if orig, contains := test[t.Host]; contains {
				// 	fmt.Printf("Duplicated host >>>[%s]<<< [%s] -- [%s]\n", t.Host, res.Name, orig.Name)
				// 	// fmt.Printf("Duplicates: orig [%s]\nnew [%s]\n", orig, res)
				// 	orig.retroactiveJoin(res, test, data)
				// 	// fmt.Printf("SuperRule [%s]\n", orig)
				// } else {
				// 	test[t.Host] = res
				// }
				if test[t.Host] == nil {
					test[t.Host] = make([]*RulesetSt, 0)
				}
				test[t.Host] = append(test[t.Host], res)
			}
		} else {
			// fmt.Printf("Disabled rule [%s] cause [%s]\n", res.Name, res.Disabled)
		}

	}

	/// we have now all the targets and rules sorted and placed in a neat way now, we can construct the hashmap
	/// ...with a twist, and an obvious one, encoding solely on the hashmap would be tedious since values repeat themselves, therefore, we create a map of [uint64]->int(index),
	/// and create a separate slice with the rule structures

	/// saves the unique indexes here
	encodeMap = make(map[int]int)
	/// have a map of hashes->target strings to decide if there's an actual collision or just a duplicate target entry (since the rule joining technique is dissolved)
	/// for now, the logic is first arrived, first served; in time will evacuate forward if more duplicates are there than not (right now 1 hash collision is present, 2017.09.12)
	collisionChecker := make(map[uint32]string)
	savedDefaultRule := false
	defaultRuleIndex := -1
	for target, objArr := range test {
		/// approach here is, that we calculate the hash for the target, we check if it's a _legit_ collision (different target producing same hash value)
		hc := hash(target)
		/// if there's a collision, move the target to forward table, and save with the larger structure (will be simplified later)
		if _, contains := data.regularMap[hc]; contains && collisionChecker[hc] != target {
			fmt.Printf("Collision detected --> moving target [%s] to forward table.\n", target)
			data.forward[target] = objArr
			continue
		}
		/// register hash in collision checker
		collisionChecker[hc] = target
		/// if that specific struct was already saved, save the reference in the current target too
		if data.regularMap[hc] == nil {
			data.regularMap[hc] = make([]int, 0)
		}
		for _, obj := range objArr {
			if index, contains := encodeMap[obj.Index]; contains {
				data.regularMap[hc] = append(data.regularMap[hc], index)
				//fmt.Printf("Already saved! [%s] -> [%s]\n", target, data.regularSlice[index])
			} else {

				simple := obj.simplify()
				if simple.isDefaultRule() && savedDefaultRule {
					data.regularMap[hc] = append(data.regularMap[hc], defaultRuleIndex)
					encodeMap[obj.Index] = defaultRuleIndex
					continue
				} else if simple.isDefaultRule() {
					defaultRuleIndex = len(data.regularSlice)
					savedDefaultRule = true
				}

				if len(simple.ruleFrom) != len(simple.ruleTo) {
					fmt.Printf("BIG PROBLEM! [%s]\n[%s]\n", simple, obj)
				}
				data.regularSlice = append(data.regularSlice, simple)
				currInd := len(data.regularSlice) - 1
				data.regularMap[hc] = append(data.regularMap[hc], currInd)
				encodeMap[obj.Index] = currInd
			}
		}
	}

	/// bragging and testing section
	fmt.Printf("Read [%d] entries, with [%d] targets grand total, [%d] total characters, and [%d] tricky wildcards\n", len(data.input), inputNum, inputStrlen, trickyNum)
	start := time.Now()
	for _, e := range data.input {
		for _, t := range e.Target {
			b := data.filter.Lookup([]byte(t.Host))
			// fmt.Printf("[%v]", b)
			if b != true {
				// fmt.Printf("#[%s]\n", t.Host)
			}
		}
	}
	fmt.Printf("Checked entries in [%v] time\n", time.Now().Sub(start))
	fmt.Printf("Filter takes around [%d] space.\n", len(data.filter.Encode()))
	fmt.Printf("Hashmap stats %d vs %d vs %d\n", len(data.regularMap), len(test), len(data.regularSlice))

	totalcharsAgain := 0
	for _, r := range data.regularSlice {
		totalcharsAgain += r.countChars()
	}
	bitnum := int(math.Ceil(math.Log2(float64(len(data.regularSlice)))))
	fmt.Printf("And again just to double check, [%d] is the total number of characters. [%d] entries --> [%d] bits to encode indexes\n", totalcharsAgain, len(data.regularSlice), bitnum)
	fmt.Printf("Map will approximately take [%d] bytes to encode.\n", 4*(len(data.regularMap)+len(data.regularSlice)+1))

	return data, nil
}
