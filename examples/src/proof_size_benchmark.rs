use std::collections::HashMap;

use csv::Writer;
use plotters::prelude::*;
use serde::Serialize;

use crate::{experiment_sha, ExampleOptions};

#[derive(Debug, Clone, Serialize)]
pub struct BenchmarkResult {
    pub parameter_name: String,
    pub parameter_value: String,
    pub proof_size_bytes: usize,
    pub blowup_factor: usize,
    pub grinding_factor: u32,
    pub field_extension: u32,
    pub folding_factor: usize,
    pub string_length: usize,
}

pub struct ProofSizeBenchmark {
    pub default_blowup: usize,
    pub default_grinding: u32,
    pub default_field_extension: u32,
    pub default_folding: usize,
    pub default_string_length: usize,
}

impl Default for ProofSizeBenchmark {
    fn default() -> Self {
        Self {
            default_blowup: 8,
            default_grinding: 16,
            default_field_extension: 1,
            default_folding: 8,
            default_string_length: 240,
        }
    }
}

impl ProofSizeBenchmark {
    pub fn new() -> Self {
        Self::default()
    }

    /// Запускает бенчмарк для всех параметров
    pub fn run_all_benchmarks(&self) -> Result<Vec<BenchmarkResult>, Box<dyn std::error::Error>> {
        let mut all_results = Vec::new();

        println!("Запуск бенчмарков размера доказательств...");

        // Бенчмарк blowup factor
        println!("Тестирование blowup factor...");
        let blowup_results = self.benchmark_blowup_factor()?;
        all_results.extend(blowup_results);

        // Бенчмарк grinding factor
        println!("Тестирование grinding factor...");
        let grinding_results = self.benchmark_grinding_factor()?;
        all_results.extend(grinding_results);

        // Бенчмарк field extension
        println!("Тестирование field extension...");
        let field_ext_results = self.benchmark_field_extension()?;
        all_results.extend(field_ext_results);

        // Бенчмарк folding factor
        println!("Тестирование folding factor...");
        let folding_results = self.benchmark_folding_factor()?;
        all_results.extend(folding_results);

        // Бенчмарк string length
        println!("Тестирование string length...");
        let string_length_results = self.benchmark_string_length()?;
        all_results.extend(string_length_results);

        Ok(all_results)
    }

    /// Бенчмарк для blowup factor
    fn benchmark_blowup_factor(&self) -> Result<Vec<BenchmarkResult>, Box<dyn std::error::Error>> {
        let blowup_values = vec![8, 16, 32, 64];
        let mut results = Vec::new();

        for &blowup in &blowup_values {
            println!("  Тестирование blowup = {}", blowup);
            let proof_size = self.measure_proof_size(
                blowup,
                self.default_grinding,
                self.default_field_extension,
                self.default_folding,
                self.default_string_length,
            )?;

            results.push(BenchmarkResult {
                parameter_name: "blowup_factor".to_string(),
                parameter_value: blowup.to_string(),
                proof_size_bytes: proof_size,
                blowup_factor: blowup,
                grinding_factor: self.default_grinding,
                field_extension: self.default_field_extension,
                folding_factor: self.default_folding,
                string_length: self.default_string_length,
            });
        }

        Ok(results)
    }

    /// Бенчмарк для grinding factor
    fn benchmark_grinding_factor(&self) -> Result<Vec<BenchmarkResult>, Box<dyn std::error::Error>> {
        let grinding_values = vec![8, 16, 20, 24, 28, 32];
        let mut results = Vec::new();

        for &grinding in &grinding_values {
            println!("  Тестирование grinding = {}", grinding);
            let proof_size = self.measure_proof_size(
                self.default_blowup,
                grinding,
                self.default_field_extension,
                self.default_folding,
                self.default_string_length,
            )?;

            results.push(BenchmarkResult {
                parameter_name: "grinding_factor".to_string(),
                parameter_value: grinding.to_string(),
                proof_size_bytes: proof_size,
                blowup_factor: self.default_blowup,
                grinding_factor: grinding,
                field_extension: self.default_field_extension,
                folding_factor: self.default_folding,
                string_length: self.default_string_length,
            });
        }

        Ok(results)
    }

    /// Бенчмарк для field extension
    fn benchmark_field_extension(&self) -> Result<Vec<BenchmarkResult>, Box<dyn std::error::Error>> {
        let field_ext_values = vec![1, 2, 3];
        let mut results = Vec::new();

        for &field_ext in &field_ext_values {
            println!("  Тестирование field_extension = {}", field_ext);
            let proof_size = self.measure_proof_size(
                self.default_blowup,
                self.default_grinding,
                field_ext,
                self.default_folding,
                self.default_string_length,
            )?;

            results.push(BenchmarkResult {
                parameter_name: "field_extension".to_string(),
                parameter_value: field_ext.to_string(),
                proof_size_bytes: proof_size,
                blowup_factor: self.default_blowup,
                grinding_factor: self.default_grinding,
                field_extension: field_ext,
                folding_factor: self.default_folding,
                string_length: self.default_string_length,
            });
        }

        Ok(results)
    }

    /// Бенчмарк для folding factor
    fn benchmark_folding_factor(&self) -> Result<Vec<BenchmarkResult>, Box<dyn std::error::Error>> {
        let folding_values = vec![8, 16];
        let mut results = Vec::new();

        for &folding in &folding_values {
            println!("  Тестирование folding = {}", folding);
            let proof_size = self.measure_proof_size(
                self.default_blowup,
                self.default_grinding,
                self.default_field_extension,
                folding,
                self.default_string_length,
            )?;

            results.push(BenchmarkResult {
                parameter_name: "folding_factor".to_string(),
                parameter_value: folding.to_string(),
                proof_size_bytes: proof_size,
                blowup_factor: self.default_blowup,
                grinding_factor: self.default_grinding,
                field_extension: self.default_field_extension,
                folding_factor: folding,
                string_length: self.default_string_length,
            });
        }

        Ok(results)
    }

    /// Бенчмарк для string length
    fn benchmark_string_length(&self) -> Result<Vec<BenchmarkResult>, Box<dyn std::error::Error>> {
        let string_length_values = vec![110, 240, 480, 1000, 2030, 4050, 8150, 16350, 32700];
        let mut results = Vec::new();

        for &string_length in &string_length_values {
            println!("  Тестирование string_length = {}", string_length);
            let proof_size = self.measure_proof_size(
                self.default_blowup,
                self.default_grinding,
                self.default_field_extension,
                self.default_folding,
                string_length,
            )?;

            results.push(BenchmarkResult {
                parameter_name: "string_length".to_string(),
                parameter_value: string_length.to_string(),
                proof_size_bytes: proof_size,
                blowup_factor: self.default_blowup,
                grinding_factor: self.default_grinding,
                field_extension: self.default_field_extension,
                folding_factor: self.default_folding,
                string_length,
            });
        }

        Ok(results)
    }

    /// Измеряет размер доказательства для заданных параметров
    fn measure_proof_size(
        &self,
        blowup_factor: usize,
        grinding_factor: u32,
        field_extension: u32,
        folding_factor: usize,
        string_length: usize,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        // Создаем опции для примера
        let options = ExampleOptions {
            example: crate::ExampleType::ExperimentSha { string_length },
            hash_fn: "blake3_256".to_string(),
            num_queries: None,
            blowup_factor: Some(blowup_factor),
            grinding_factor,
            field_extension,
            folding_factor,
        };

        // Получаем пример
        let example = experiment_sha::get_example(&options, string_length)?;

        // Генерируем доказательство
        let proof = example.prove();

        // Получаем размер доказательства в байтах
        let proof_bytes = proof.to_bytes();
        
        Ok(proof_bytes.len())
    }

    /// Сохраняет результаты в CSV файл
    pub fn save_results_to_csv(
        &self,
        results: &[BenchmarkResult],
        filename: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Создаем директорию если она не существует
        if let Some(parent) = std::path::Path::new(filename).parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        let mut wtr = Writer::from_path(filename)?;

        for result in results {
            wtr.serialize(result)?;
        }

        wtr.flush()?;
        println!("Результаты сохранены в {}", filename);
        Ok(())
    }

    /// Создает графики для каждого параметра
    pub fn create_plots(
        &self,
        results: &[BenchmarkResult],
        output_dir: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Создаем директорию если она не существует
        std::fs::create_dir_all(output_dir)?;

        // Группируем результаты по параметрам
        let mut grouped_results: HashMap<String, Vec<&BenchmarkResult>> = HashMap::new();
        for result in results {
            grouped_results
                .entry(result.parameter_name.clone())
                .or_insert_with(Vec::new)
                .push(result);
        }

        // Создаем график для каждого параметра
        for (param_name, param_results) in grouped_results {
            self.create_single_plot(&param_name, &param_results, output_dir)?;
        }

        Ok(())
    }

    /// Создает график для одного параметра
    fn create_single_plot(
        &self,
        param_name: &str,
        results: &[&BenchmarkResult],
        output_dir: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Создаем подпапку с количеством колонок
        let subdir = format!("{}/columns_{}", output_dir, experiment_sha::table_constants::TABLE_WIDTH);
        std::fs::create_dir_all(&subdir)?;
        
        let filename = format!("{}/{}_vs_proof_size.png", subdir, param_name);
        let root = BitMapBackend::new(&filename, (800, 600)).into_drawing_area();
        root.fill(&WHITE)?;

        // Подготавливаем данные
        let mut data: Vec<(f64, f64)> = results
            .iter()
            .map(|r| {
                let x_val = match param_name {
                    "string_length" => r.string_length as f64,
                    "blowup_factor" => r.blowup_factor as f64,
                    "grinding_factor" => r.grinding_factor as f64,
                    "field_extension" => r.field_extension as f64,
                    "folding_factor" => r.folding_factor as f64,
                    _ => 0.0,
                };
                (x_val, r.proof_size_bytes as f64)
            })
            .collect();

        data.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

        if data.is_empty() {
            return Ok(());
        }

        let x_min = data.iter().map(|(x, _)| *x).fold(f64::INFINITY, f64::min);
        let x_max = data.iter().map(|(x, _)| *x).fold(f64::NEG_INFINITY, f64::max);
        let y_min = data.iter().map(|(_, y)| *y).fold(f64::INFINITY, f64::min);
        let y_max = data.iter().map(|(_, y)| *y).fold(f64::NEG_INFINITY, f64::max);

        let x_margin = (x_max - x_min) * 0.1;
        let y_margin = (y_max - y_min) * 0.1;

        let mut chart = ChartBuilder::on(&root)
            .caption(
                &format!("Размер доказательства vs {}", param_name),
                ("sans-serif", 30),
            )
            .margin(10)
            .x_label_area_size(40)
            .y_label_area_size(60)
            .build_cartesian_2d(
                (x_min - x_margin)..(x_max + x_margin),
                (y_min - y_margin)..(y_max + y_margin),
            )?;

        chart
            .configure_mesh()
            .x_desc(param_name)
            .y_desc("Размер доказательства (байты)")
            .draw()?;

        chart
            .draw_series(LineSeries::new(data.iter().cloned(), &BLUE))?
            .label("Размер доказательства")
            .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 10, y)], &BLUE));

        chart
            .draw_series(PointSeries::of_element(
                data.iter().cloned(),
                5,
                &BLUE,
                &|c, s, st| {
                    return EmptyElement::at(c)    // We want to construct a composed element on-the-fly
                        + Circle::new((0, 0), s, st.filled()); // At this point, the new pixel coordinate is established
                },
            ))?;

        chart.configure_series_labels().draw()?;
        root.present()?;

        println!("График сохранен: {}", filename);
        Ok(())
    }
}
