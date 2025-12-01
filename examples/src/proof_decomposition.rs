//! Инструмент для декомпозиции и анализа структуры STARK доказательства.
//! 
//! Этот модуль позволяет разбить доказательство на составные части и измерить
//! размер каждой части, чтобы понять, какие компоненты занимают больше всего места.
//!
//! # Пример использования
//! ```no_run
//! use examples::proof_decomposition::ProofDecomposition;
//! use winterfell::Proof;
//!
//! let proof: Proof = /* ... */;
//! let decomposition = ProofDecomposition::analyze(&proof);
//! decomposition.print_report();
//! ```

use winterfell::Proof;
use air::proof::{Commitments, Queries, OodFrame};
use fri::FriProof;
use core_utils::{ByteWriter, Serializable, SliceReader, Deserializable, ByteReader};

/// Детальная информация о размерах компонентов доказательства
#[derive(Debug, Clone)]
pub struct ProofDecomposition {
    /// Общий размер доказательства в байтах
    pub total_size: usize,
    
    /// Размер контекста (метаданные о вычислении)
    pub context_size: usize,
    
    /// Размер num_unique_queries (1 байт)
    pub num_unique_queries_size: usize,
    
    /// Размер commitments (коммитменты к трейсу, constraints и FRI слоям)
    pub commitments_size: usize,
    
    /// Размеры trace_queries для каждого сегмента трейса
    pub trace_queries_sizes: Vec<usize>,
    
    /// Общий размер всех trace_queries
    pub trace_queries_total_size: usize,
    
    /// Размер constraint_queries
    pub constraint_queries_size: usize,
    
    /// Размер ood_frame (out-of-domain evaluations)
    pub ood_frame_size: usize,
    
    /// Размер fri_proof (FRI доказательство низкой степени)
    pub fri_proof_size: usize,
    
    /// Детальная декомпозиция FRI доказательства
    pub fri_decomposition: FriDecomposition,
    
    /// Размер pow_nonce (8 байт)
    pub pow_nonce_size: usize,
    
    /// Детальная информация о commitments
    pub commitments_decomposition: CommitmentsDecomposition,
    
    /// Детальная информация о trace queries
    pub trace_queries_decomposition: Vec<QueriesDecomposition>,
    
    /// Детальная информация о constraint queries
    pub constraint_queries_decomposition: QueriesDecomposition,
    
    /// Детальная информация о OOD frame
    pub ood_frame_decomposition: OodFrameDecomposition,
}

/// Детальная декомпозиция FRI доказательства
#[derive(Debug, Clone)]
pub struct FriDecomposition {
    /// Общий размер FRI доказательства
    pub total_size: usize,
    
    /// Количество слоев FRI
    pub num_layers: usize,
    
    /// Размеры каждого слоя FRI
    pub layer_sizes: Vec<FriLayerDecomposition>,
    
    /// Размер remainder (последний слой FRI)
    pub remainder_size: usize,
    
    /// Размер метаданных (количество слоев, размер remainder, количество партиций)
    pub metadata_size: usize,
}

/// Декомпозиция одного слоя FRI
#[derive(Debug, Clone)]
pub struct FriLayerDecomposition {
    /// Номер слоя (начиная с 0)
    pub layer_index: usize,
    
    /// Общий размер слоя
    pub total_size: usize,
    
    /// Размер значений (query values)
    pub values_size: usize,
    
    /// Размер путей (opening proofs)
    pub paths_size: usize,
    
    /// Размер метаданных (длины values и paths)
    pub metadata_size: usize,
}

/// Декомпозиция commitments
#[derive(Debug, Clone)]
pub struct CommitmentsDecomposition {
    /// Общий размер commitments
    pub total_size: usize,
    
    /// Размер метаданных (длина вектора байт)
    pub metadata_size: usize,
    
    /// Размер внутренних данных (trace roots, constraint root, FRI roots)
    pub data_size: usize,
}

/// Декомпозиция queries (trace или constraint)
#[derive(Debug, Clone)]
pub struct QueriesDecomposition {
    /// Общий размер queries
    pub total_size: usize,
    
    /// Размер значений (evaluations)
    pub values_size: usize,
    
    /// Размер opening proofs
    pub opening_proof_size: usize,
}

/// Декомпозиция OOD frame
#[derive(Debug, Clone)]
pub struct OodFrameDecomposition {
    /// Общий размер OOD frame
    pub total_size: usize,
    
    /// Размер trace states
    pub trace_states_size: usize,
    
    /// Размер quotient states
    pub quotient_states_size: usize,
    
    /// Размер метаданных (длины trace_states и quotient_states)
    pub metadata_size: usize,
}

impl ProofDecomposition {
    /// Создает декомпозицию доказательства, анализируя его структуру
    pub fn analyze(proof: &Proof) -> Self {
        // Сериализуем каждую часть отдельно для измерения размера
        let context_size = proof.context.to_bytes().len();
        let num_unique_queries_size = 1; // u8
        let commitments_size = proof.commitments.to_bytes().len();
        
        // Анализируем trace queries
        let mut trace_queries_sizes = Vec::new();
        let mut trace_queries_decomposition = Vec::new();
        let mut trace_queries_total_size = 0;
        
        for (idx, trace_query) in proof.trace_queries.iter().enumerate() {
            let size = trace_query.to_bytes().len();
            trace_queries_sizes.push(size);
            trace_queries_total_size += size;
            
            // Для детальной декомпозиции используем десериализацию через SliceReader
            // Queries сериализуется как: values (Vec<u8>) + opening_proof (Vec<u8>)
            let queries_bytes = trace_query.to_bytes();
            let mut reader = SliceReader::new(&queries_bytes);
            
            // Читаем values (Vec<u8>) - Vec сериализуется как usize (vint64) + данные
            let values_size = if let Ok(len) = reader.read_usize() {
                if let Ok(data) = reader.read_vec(len) {
                    data.len()
                } else {
                    0
                }
            } else {
                0
            };
            
            // Читаем opening_proof (Vec<u8>)
            let opening_proof_size = if let Ok(len) = reader.read_usize() {
                if let Ok(data) = reader.read_vec(len) {
                    data.len()
                } else {
                    0
                }
            } else {
                0
            };
            
            let queries_decomp = QueriesDecomposition {
                total_size: size,
                values_size,
                opening_proof_size,
            };
            trace_queries_decomposition.push(queries_decomp);
        }
        
        // Анализируем constraint queries
        let constraint_queries_size = proof.constraint_queries.to_bytes().len();
        let constraint_queries_bytes = proof.constraint_queries.to_bytes();
        let mut reader = SliceReader::new(&constraint_queries_bytes);
        
        let values_size = if let Ok(len) = reader.read_usize() {
            if let Ok(data) = reader.read_vec(len) {
                data.len()
            } else {
                0
            }
        } else {
            0
        };
        
        let opening_proof_size = if let Ok(len) = reader.read_usize() {
            if let Ok(data) = reader.read_vec(len) {
                data.len()
            } else {
                0
            }
        } else {
            0
        };
        
        let constraint_queries_decomposition = QueriesDecomposition {
            total_size: constraint_queries_size,
            values_size,
            opening_proof_size,
        };
        
        // Анализируем OOD frame
        let ood_frame_size = proof.ood_frame.to_bytes().len();
        let ood_frame_bytes = proof.ood_frame.to_bytes();
        let mut reader = SliceReader::new(&ood_frame_bytes);
        
        // OOD frame сериализуется как: u16 (trace_states len) + trace_states + u16 (quotient_states len) + quotient_states
        let trace_states_size = if let Ok(len) = reader.read_u16() {
            let len = len as usize;
            if let Ok(data) = reader.read_vec(len) {
                data.len()
            } else {
                0
            }
        } else {
            0
        };
        
        let quotient_states_size = if let Ok(len) = reader.read_u16() {
            let len = len as usize;
            if let Ok(data) = reader.read_vec(len) {
                data.len()
            } else {
                0
            }
        } else {
            0
        };
        
        let ood_frame_decomposition = OodFrameDecomposition {
            total_size: ood_frame_size,
            trace_states_size,
            quotient_states_size,
            metadata_size: 4, // 2 u16 для длин
        };
        
        // Анализируем FRI proof
        let fri_proof_size = proof.fri_proof.to_bytes().len();
        let fri_decomposition = FriDecomposition::analyze(&proof.fri_proof);
        
        // Анализируем commitments
        // Commitments сериализуется как: u16 (len) + Vec<u8>
        let commitments_bytes = proof.commitments.to_bytes();
        let mut reader = SliceReader::new(&commitments_bytes);
        let data_size = if let Ok(len) = reader.read_u16() {
            let len = len as usize;
            if let Ok(data) = reader.read_vec(len) {
                data.len()
            } else {
                0
            }
        } else {
            0
        };
        
        let commitments_decomposition = CommitmentsDecomposition {
            total_size: commitments_size,
            metadata_size: 2, // u16 для длины
            data_size,
        };
        
        let pow_nonce_size = 8; // u64
        
        let total_size = proof.to_bytes().len();
        
        Self {
            total_size,
            context_size,
            num_unique_queries_size,
            commitments_size,
            trace_queries_sizes,
            trace_queries_total_size,
            constraint_queries_size,
            ood_frame_size,
            fri_proof_size,
            fri_decomposition,
            pow_nonce_size,
            commitments_decomposition,
            trace_queries_decomposition,
            constraint_queries_decomposition,
            ood_frame_decomposition,
        }
    }
    
    /// Выводит детальный отчет о структуре доказательства
    pub fn print_report(&self) {
        println!("\n╔══════════════════════════════════════════════════════════════════════════════╗");
        println!("║                    ДЕКОМПОЗИЦИЯ STARK ДОКАЗАТЕЛЬСТВА                        ║");
        println!("╚══════════════════════════════════════════════════════════════════════════════╝\n");
        
        println!("Общий размер доказательства: {:.2} KB ({} байт)\n", 
                 self.total_size as f64 / 1024.0, self.total_size);
        
        // Основные компоненты
        println!("┌──────────────────────────────────────────────────────────────────────────────┐");
        println!("│ ОСНОВНЫЕ КОМПОНЕНТЫ                                                          │");
        println!("└──────────────────────────────────────────────────────────────────────────────┘\n");
        
        self.print_component("Context (метаданные)", self.context_size, self.total_size);
        self.print_component("Commitments", self.commitments_size, self.total_size);
        self.print_component("Trace Queries (всего)", self.trace_queries_total_size, self.total_size);
        self.print_component("Constraint Queries", self.constraint_queries_size, self.total_size);
        self.print_component("OOD Frame", self.ood_frame_size, self.total_size);
        self.print_component("FRI Proof", self.fri_proof_size, self.total_size);
        self.print_component("Num Unique Queries", self.num_unique_queries_size, self.total_size);
        self.print_component("POW Nonce", self.pow_nonce_size, self.total_size);
        
        // Детальная информация о commitments
        println!("\n┌──────────────────────────────────────────────────────────────────────────────┐");
        println!("│ COMMITMENTS (Детализация)                                                     │");
        println!("└──────────────────────────────────────────────────────────────────────────────┘\n");
        println!("  Общий размер: {:.2} KB ({} байт)", 
                 self.commitments_size as f64 / 1024.0, self.commitments_size);
        println!("  ├─ Метаданные (длина): {} байт", self.commitments_decomposition.metadata_size);
        println!("  └─ Данные (trace roots + constraint root + FRI roots): {:.2} KB ({} байт)",
                 self.commitments_decomposition.data_size as f64 / 1024.0,
                 self.commitments_decomposition.data_size);
        
        // Детальная информация о trace queries
        println!("\n┌──────────────────────────────────────────────────────────────────────────────┐");
        println!("│ TRACE QUERIES (Детализация)                                                   │");
        println!("└──────────────────────────────────────────────────────────────────────────────┘\n");
        println!("  Общий размер всех trace queries: {:.2} KB ({} байт)",
                 self.trace_queries_total_size as f64 / 1024.0, self.trace_queries_total_size);
        println!("  Количество сегментов трейса: {}\n", self.trace_queries_sizes.len());
        
        for (idx, (size, decomp)) in self.trace_queries_sizes.iter()
            .zip(self.trace_queries_decomposition.iter()).enumerate() {
            println!("  Сегмент {}:", idx);
            println!("    Общий размер: {:.2} KB ({} байт)", 
                     *size as f64 / 1024.0, size);
            println!("    ├─ Values (evaluations): {:.2} KB ({} байт)",
                     decomp.values_size as f64 / 1024.0, decomp.values_size);
            println!("    └─ Opening proofs: {:.2} KB ({} байт)",
                     decomp.opening_proof_size as f64 / 1024.0, decomp.opening_proof_size);
        }
        
        // Детальная информация о constraint queries
        println!("\n┌──────────────────────────────────────────────────────────────────────────────┐");
        println!("│ CONSTRAINT QUERIES (Детализация)                                              │");
        println!("└──────────────────────────────────────────────────────────────────────────────┘\n");
        println!("  Общий размер: {:.2} KB ({} байт)",
                 self.constraint_queries_size as f64 / 1024.0, self.constraint_queries_size);
        println!("  ├─ Values (evaluations): {:.2} KB ({} байт)",
                 self.constraint_queries_decomposition.values_size as f64 / 1024.0,
                 self.constraint_queries_decomposition.values_size);
        println!("  └─ Opening proofs: {:.2} KB ({} байт)",
                 self.constraint_queries_decomposition.opening_proof_size as f64 / 1024.0,
                 self.constraint_queries_decomposition.opening_proof_size);
        
        // Детальная информация о OOD frame
        println!("\n┌──────────────────────────────────────────────────────────────────────────────┐");
        println!("│ OOD FRAME (Детализация)                                                       │");
        println!("└──────────────────────────────────────────────────────────────────────────────┘\n");
        println!("  Общий размер: {:.2} KB ({} байт)",
                 self.ood_frame_size as f64 / 1024.0, self.ood_frame_size);
        println!("  ├─ Метаданные (длины): {} байт", self.ood_frame_decomposition.metadata_size);
        println!("  ├─ Trace states: {:.2} KB ({} байт)",
                 self.ood_frame_decomposition.trace_states_size as f64 / 1024.0,
                 self.ood_frame_decomposition.trace_states_size);
        println!("  └─ Quotient states: {:.2} KB ({} байт)",
                 self.ood_frame_decomposition.quotient_states_size as f64 / 1024.0,
                 self.ood_frame_decomposition.quotient_states_size);
        
        // Детальная информация о FRI proof
        println!("\n┌──────────────────────────────────────────────────────────────────────────────┐");
        println!("│ FRI PROOF (Детализация)                                                       │");
        println!("└──────────────────────────────────────────────────────────────────────────────┘\n");
        println!("  Общий размер: {:.2} KB ({} байт)",
                 self.fri_proof_size as f64 / 1024.0, self.fri_proof_size);
        println!("  Количество слоев: {}", self.fri_decomposition.num_layers);
        println!("  Метаданные (количество слоев, размер remainder, партиции): {} байт",
                 self.fri_decomposition.metadata_size);
        println!("  Remainder (последний слой): {:.2} KB ({} байт)\n",
                 self.fri_decomposition.remainder_size as f64 / 1024.0,
                 self.fri_decomposition.remainder_size);
        
        for layer in &self.fri_decomposition.layer_sizes {
            println!("  Слой {}:", layer.layer_index);
            println!("    Общий размер: {:.2} KB ({} байт)",
                     layer.total_size as f64 / 1024.0, layer.total_size);
            println!("    ├─ Метаданные (длины): {} байт", layer.metadata_size);
            println!("    ├─ Values (query values): {:.2} KB ({} байт)",
                     layer.values_size as f64 / 1024.0, layer.values_size);
            println!("    └─ Paths (opening proofs): {:.2} KB ({} байт)",
                     layer.paths_size as f64 / 1024.0, layer.paths_size);
        }
        
        // Итоговая таблица с процентами
        println!("\n┌──────────────────────────────────────────────────────────────────────────────┐");
        println!("│ ИТОГОВАЯ ТАБЛИЦА (размеры и проценты)                                        │");
        println!("└──────────────────────────────────────────────────────────────────────────────┘\n");
        
        let mut components = vec![
            ("Context", self.context_size),
            ("Commitments", self.commitments_size),
            ("Trace Queries", self.trace_queries_total_size),
            ("Constraint Queries", self.constraint_queries_size),
            ("OOD Frame", self.ood_frame_size),
            ("FRI Proof", self.fri_proof_size),
            ("Num Unique Queries", self.num_unique_queries_size),
            ("POW Nonce", self.pow_nonce_size),
        ];
        
        // Сортируем по размеру (от большего к меньшему)
        components.sort_by(|a, b| b.1.cmp(&a.1));
        
        println!("{:<25} {:>12} {:>10} {:>8}", "Компонент", "Байт", "KB", "%");
        println!("{}", "-".repeat(60));
        
        for (name, size) in &components {
            let kb = *size as f64 / 1024.0;
            let percent = (*size as f64 / self.total_size as f64) * 100.0;
            println!("{:<25} {:>12} {:>10.2} {:>7.2}%", name, size, kb, percent);
        }
        
        println!("{}", "-".repeat(60));
        println!("{:<25} {:>12} {:>10.2} {:>7.2}%", 
                 "ИТОГО", self.total_size, self.total_size as f64 / 1024.0, 100.0);
    }
    
    fn print_component(&self, name: &str, size: usize, total: usize) {
        let kb = size as f64 / 1024.0;
        let percent = (size as f64 / total as f64) * 100.0;
        println!("  {:<30} {:>10} байт ({:>6.2} KB, {:>5.2}%)",
                 name, size, kb, percent);
    }
}

impl FriDecomposition {
    fn analyze(fri_proof: &FriProof) -> Self {
        let num_layers = fri_proof.num_layers();
        let mut layer_sizes = Vec::new();
        
        // Сериализуем FRI proof для анализа
        let fri_bytes = fri_proof.to_bytes();
        let mut offset = 0;
        
        // Читаем количество слоев (u8)
        if offset >= fri_bytes.len() {
            return Self {
                total_size: fri_bytes.len(),
                num_layers: 0,
                layer_sizes: Vec::new(),
                remainder_size: 0,
                metadata_size: 0,
            };
        }
        
        let num_layers_byte = fri_bytes[offset];
        offset += 1;
        
        // Читаем каждый слой
        for idx in 0..num_layers_byte as usize {
            if offset + 4 > fri_bytes.len() {
                break;
            }
            
            // Читаем размер values (u32)
            let values_len_bytes: [u8; 4] = fri_bytes[offset..offset+4].try_into().unwrap();
            let values_len = u32::from_le_bytes(values_len_bytes) as usize;
            offset += 4;
            
            if offset + values_len > fri_bytes.len() {
                break;
            }
            let values_size = values_len;
            offset += values_len;
            
            // Читаем размер paths (u32)
            if offset + 4 > fri_bytes.len() {
                break;
            }
            let paths_len_bytes: [u8; 4] = fri_bytes[offset..offset+4].try_into().unwrap();
            let paths_len = u32::from_le_bytes(paths_len_bytes) as usize;
            offset += 4;
            
            if offset + paths_len > fri_bytes.len() {
                break;
            }
            let paths_size = paths_len;
            offset += paths_len;
            
            let metadata_size = 8; // 2 u32 для длин
            let total_size = values_size + paths_size + metadata_size;
            
            layer_sizes.push(FriLayerDecomposition {
                layer_index: idx,
                total_size,
                values_size,
                paths_size,
                metadata_size,
            });
        }
        
        // Читаем remainder (u16 для длины + данные)
        let remainder_size = if offset + 2 <= fri_bytes.len() {
            let remainder_len_bytes: [u8; 2] = fri_bytes[offset..offset+2].try_into().unwrap();
            let remainder_len = u16::from_le_bytes(remainder_len_bytes) as usize;
            offset += 2;
            if offset + remainder_len <= fri_bytes.len() {
                remainder_len
            } else {
                0
            }
        } else {
            0
        };
        
        // Метаданные: u8 для количества слоев, u16 для размера remainder, u8 для партиций
        let metadata_size = 1 + 2 + 1; // 4 байта
        
        let total_size = fri_proof.size();
        
        Self {
            total_size,
            num_layers: num_layers_byte as usize,
            layer_sizes,
            remainder_size,
            metadata_size,
        }
    }
}


