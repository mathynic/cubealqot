//! M7-11 tests for exact filtering of backend integral points.

use cubealqot::family::{
    CanonicalInt, PointDecision, PointFilterStatus, PointRejectionReason, UntrustedIntegralPoint,
    filter_integral_points,
};
use cubealqot::family::{pocklington::UntrustedPrimeCertificate, problem};

fn integer(value: &str) -> CanonicalInt {
    CanonicalInt::from_decimal(value).expect("fixture integer is canonical")
}

fn factor(prime: &str, exponent: u32) -> problem::UntrustedCofactorFactor {
    problem::UntrustedCofactorFactor {
        prime: integer(prime),
        exponent,
        certificate: Some(UntrustedPrimeCertificate::U64 { n: integer(prime) }),
    }
}

fn n9() -> problem::Problem {
    match problem::validate_problem(&problem::UntrustedProblem {
        n: integer("9"),
        factors: vec![factor("3", 2)],
    }) {
        problem::ProblemBuildResult::Certified(problem) => problem,
        other => panic!("expected certified problem, got {other:?}"),
    }
}

fn point(x: &str, y: &str) -> UntrustedIntegralPoint {
    UntrustedIntegralPoint {
        x: integer(x),
        y: integer(y),
    }
}

#[test]
fn original_curve_is_checked_before_family_filters() {
    let result = filter_integral_points(&n9(), &[point("-364", "9829")]);

    assert!(matches!(result.status(), PointFilterStatus::Filtered));
    assert!(matches!(
        &result.decisions()[0].decision,
        PointDecision::Discarded {
            reason: PointRejectionReason::OffCurve
        }
    ));
    assert!(result.accepted().is_empty());
}

#[test]
fn valid_curve_points_are_checked_for_exact_divisibility_and_range() {
    // For N=9, X=-364, Y=+/-9828 is the exact curve point corresponding to
    // q=-1, while (336,+/-20972) is another exact curve point whose X is not
    // divisible by D=364.
    let result = filter_integral_points(
        &n9(),
        &[
            point("336", "20972"),
            point("-364", "9828"),
            point("-364", "-9828"),
        ],
    );

    assert!(result.accepted().is_empty());
    assert!(matches!(
        &result.decisions()[0].decision,
        PointDecision::Discarded {
            reason: PointRejectionReason::MissingXDivisibility
        }
    ));
    assert!(matches!(
        &result.decisions()[1].decision,
        PointDecision::Discarded {
            reason: PointRejectionReason::QOutOfRange
        }
    ));
    assert!(matches!(
        &result.decisions()[2].decision,
        PointDecision::Discarded {
            reason: PointRejectionReason::QOutOfRange
        }
    ));
}

#[test]
fn huge_coordinates_are_not_narrowed_and_rational_wire_values_are_rejected() {
    let result = filter_integral_points(
        &n9(),
        &[point("340282366920938463463374607431768211456", "0")],
    );
    assert!(matches!(
        &result.decisions()[0].decision,
        PointDecision::Discarded {
            reason: PointRejectionReason::OffCurve
        }
    ));

    let rational = r#"{"x":"1/2","y":"3"}"#;
    assert!(serde_json::from_str::<UntrustedIntegralPoint>(rational).is_err());
}
