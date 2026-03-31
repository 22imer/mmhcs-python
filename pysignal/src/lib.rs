use pyo3::prelude::*;

#[pyfunction]
fn hello() -> PyResult<String> {
    Ok("libsignal (PQXDH-ready) is wired up!".to_string())
}

#[pymodule]
fn pysignal(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hello, m)?)?;
    Ok(())
}