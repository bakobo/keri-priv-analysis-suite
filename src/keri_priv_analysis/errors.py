"""Every error this suite raises, declared once at module scope (dev/standards/error-codes.md)."""

from bakobo.errors import ErrorCode

COMPARTMENT_NAME = ErrorCode(
    "e.input.format.compartment-name.f",
    "A compartment name is not one the suite knows.",
    detail="{name!r} is not a compartment name. A name is a kind from {kinds}, followed by "
    "':<instance>' for the kinds that have instances.",
    args=("name", "kinds"),
    hint="Check the spelling against docs/test-plan.md, 'Compartments the adapters expose'.",
)
COMPARTMENT_STATUS = ErrorCode(
    "e.input.range.compartment-status.f",
    "A compartment's status is not present, absent or not-measured.",
    detail="Compartment {name} has status {status!r}, which is not one of present, absent or "
    "not-measured.",
    args=("name", "status"),
)
COMPARTMENT_CONTENTS = ErrorCode(
    "e.input.multi.compartment-contents.f",
    "A compartment marked absent or not measured carries contents.",
    detail="Compartment {name} is marked {status} but carries contents. Only a present "
    "compartment may hold data, so that an unmeasured one can never be read as empty.",
    args=("name", "status"),
)
COMPARTMENT_DUPLICATE = ErrorCode(
    "e.input.multi.compartment-duplicate.f",
    "Two compartments share a name.",
    detail="Compartment {name} appears more than once.",
    args=("name",),
)
COMPARTMENT_MISSING = ErrorCode(
    "e.state.missing.compartment.f",
    "A compartment was asked for that the run does not have.",
    detail="Compartment {name} is not among the run's compartments, so it cannot be handed to a "
    "party.",
    args=("name",),
)
NODE_FORMAT = ErrorCode(
    "e.input.format.node.f",
    "A join names a node in an unknown form.",
    detail="{node!r} is not a node. A node is p:<presentation handle>, id:<identity record> or "
    "x:<identifier>.",
    args=("node",),
)
RUN_COMPARTMENTS_MISSING = ErrorCode(
    "e.state.missing.run-compartments.f",
    "The run directory holds no compartments.",
    detail="{path} has no compartments/index.json, so there is nothing for an attack to read.",
    args=("path",),
    hint="Run the scenario first, or point at the run's own directory.",
)
POPULATION_SIZE = ErrorCode(
    "e.input.range.population-size.f",
    "The population size is not positive.",
    detail="The population size is {size}; it must be at least 1.",
    args=("size",),
)
POPULATION_MARGINAL = ErrorCode(
    "e.input.range.population-marginal.f",
    "An attribute's marginal distribution is malformed.",
    detail="Attribute {name} has {values} values and {probabilities} probabilities summing to "
    "{total}. There must be one probability per value, summing to 1.",
    args=("name", "values", "probabilities", "total"),
)
POPULATION_ATTRIBUTE = ErrorCode(
    "e.input.range.population-attribute.f",
    "The population model refers to an attribute it does not declare.",
    detail="{name!r} is not a declared attribute of the population.",
    args=("name",),
)
POPULATION_ATTRIBUTE_DUPLICATE = ErrorCode(
    "e.input.multi.population-attribute.f",
    "Two population attributes share a name.",
    detail="Attribute {name} is declared more than once.",
    args=("name",),
)
POPULATION_CORRELATION = ErrorCode(
    "e.input.range.population-correlation.f",
    "The declared correlations are not a valid correlation matrix.",
    detail="{reason}",
    args=("reason",),
    hint="Each correlation lies in [-1, 1], and together they must form a positive definite "
    "matrix.",
)
POPULATION_HOMES = ErrorCode(
    "e.input.range.population-homes.f",
    "The number of issuing homes is not positive.",
    detail="The population declares {homes} issuing homes; there must be at least one.",
    args=("homes",),
)
POPULATION_VALUE = ErrorCode(
    "e.input.range.population-value.f",
    "An attribute value is not one the population declares.",
    detail="Attribute {name} has no value {value!r}.",
    args=("name", "value"),
)
SCENARIO_SIZE = ErrorCode(
    "e.input.range.scenario-size.f",
    "The scenario file is too large to be a scenario.",
    detail="The scenario is {size} bytes; the limit is {limit}.",
    args=("size", "limit"),
)
SCENARIO_FORMAT = ErrorCode(
    "e.input.format.scenario.f",
    "The scenario is not valid TOML.",
    detail="The scenario could not be parsed as TOML: {reason}",
    args=("reason",),
)
SCENARIO_MISSING = ErrorCode(
    "e.input.missing.scenario-parameter.f",
    "A scenario parameter is unset.",
    detail="The scenario does not set {param}. Every parameter must be set, so that nothing a run "
    "depends on is a default nobody chose.",
    args=("param",),
)
SCENARIO_UNKNOWN = ErrorCode(
    "e.input.format.scenario-parameter.f",
    "A scenario parameter is unknown or has the wrong type.",
    detail="{param}: {reason}",
    args=("param", "reason"),
)
SCENARIO_RANGE = ErrorCode(
    "e.input.range.scenario-parameter.f",
    "A scenario parameter's value is out of range.",
    detail="{param} is {value!r}: {reason}",
    args=("param", "value", "reason"),
)
SCENARIO_COMPARTMENT = ErrorCode(
    "e.input.range.scenario-compartment.f",
    "A party names a compartment the scenario does not have.",
    detail="{param} names {name}, which this scenario does not have: {reason}",
    args=("param", "name", "reason"),
)
SCENARIO_PARTY_KIND = ErrorCode(
    "e.input.range.scenario-party-kind.f",
    "A party's kind is not one of the five.",
    detail="Party {party} has kind {kind!r}; the kinds are {kinds}.",
    args=("party", "kind", "kinds"),
)
SCENARIO_GOVERNMENT_TERMS = ErrorCode(
    "e.input.multi.scenario-government-terms.f",
    "A government party is given terms that bind it.",
    detail="Party {party} compels disclosure as a government party, which may override any terms, "
    "so it cannot be treated as bound by terms (this.i 2leqqwzy).",
    args=("party",),
)
SCENARIO_NAME = ErrorCode(
    "e.input.multi.scenario-name.f",
    "Two things in the scenario share a name.",
    detail="{param} {name!r} is declared more than once.",
    args=("param", "name"),
)
CESR_FORMAT = ErrorCode(
    "e.input.format.cesr.f",
    "A CESR stream does not parse.",
    detail="{name} does not parse as a CESR stream of KERI and ACDC messages: {reason}",
    args=("name", "reason"),
)
ADAPTER_UNAVAILABLE = ErrorCode(
    "e.feature.unsupported.adapter.f",
    "The scenario names an adapter this environment does not have.",
    detail="Adapter {adapter} is not installed here. The installed adapters are {installed}.",
    args=("adapter", "installed"),
    hint="Run the scenario from the adapter's own project under adapters/, which installs it.",
)
ADAPTER_CONTRACT = ErrorCode(
    "e.party.adapter-contract.f",
    "The adapter broke the adapter contract, so nothing it exported is scored.",
    detail="Adapter {adapter} failed {count} contract checks; the first: {first}",
    args=("adapter", "count", "first"),
)
ADAPTER_SETTING = ErrorCode(
    "e.feature.unsupported.stack-setting.f",
    "The scenario asks the stack for a setting it does not implement.",
    detail="Adapter {adapter} cannot run with {setting} = {value!r}: {reason}",
    args=("adapter", "setting", "value", "reason"),
    hint="Score a countermeasure no stack implements on the synthetic generator.",
)
RUN_EXISTS = ErrorCode(
    "e.state.conflict.run-directory.f",
    "The run directory already holds a run.",
    detail="{path} is not empty. A run never overwrites another, so a disputed number can always "
    "be recomputed from the directory that produced it.",
    args=("path",),
)
REPORT_WORD = ErrorCode(
    "e.rule.report-word.f",
    "The report would claim unlinkability, which it never does.",
    detail="The rendered report contains {word!r}. Results state joins, bits and cost, never "
    "that something cannot be linked (this.i 8q5ylk4q); the text came from {source}.",
    args=("word", "source"),
    hint="Rename the party, claim or domain in the scenario that carries the word.",
)
STREAM_SHAPE = ErrorCode(
    "e.input.format.stream-shape.f",
    "A stream holds a message or document of a kind its name does not allow.",
    detail="{name}: {reason}",
    args=("name", "reason"),
)
TIME_VALUE = ErrorCode(
    "e.input.range.compartment-time.f",
    "A compartment carries a time that is not a finite number.",
    detail="Compartment {name} has a {what} at time {time!r}; every time is a finite number of "
    "seconds from the scenario's start.",
    args=("name", "what", "time"),
)
