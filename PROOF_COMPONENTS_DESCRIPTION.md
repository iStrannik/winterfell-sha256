# Описание компонентов STARK доказательства

## Общая структура

STARK доказательство состоит из следующих основных компонентов:

1. **Context** - метаданные о вычислении
2. **Commitments** - коммитменты к данным
3. **Trace Queries** - декоммитменты значений трейса в запрошенных точках
4. **Constraint Queries** - декоммитменты значений constraint полиномов в запрошенных точках
5. **OOD Frame** - оценки полиномов вне домена
6. **FRI Proof** - доказательство низкой степени полинома
7. **POW Nonce** - nonce для proof-of-work

---

## 1. Context (Контекст)

### Что хранится:
- **TraceInfo** - информация о трейсе выполнения:
  - Ширина трейса (количество колонок)
  - Длина трейса (количество строк)
  - Количество сегментов трейса
  - Метаданные о трейсе
- **Field Modulus Bytes** - байты модуля поля (для определения поля, в котором работает протокол)
- **ProofOptions** - параметры протокола:
  - Количество запросов (queries)
  - Blowup factor
  - Grinding factor
  - Field extension
  - FRI folding factor
  - FRI remainder max degree
  - Методы батчинга
- **Number of Constraints** - общее количество ограничений (constraints) в AIR

### От чего зависит размер:
- **Размер поля**: больше поле → больше байт для модуля
- **Сложность AIR**: больше constraints → больше места для их количества
- **Структура трейса**: больше сегментов/колонок → больше метаданных
- **Размер фиксированный и небольшой** (обычно < 1 KB)

---

## 2. Commitments (Коммитменты)

### Что хранится:
- **Trace Roots** - корни Merkle деревьев для каждого сегмента расширенного трейса выполнения
  - Количество корней = количество сегментов трейса
  - Каждый корень - это хеш (digest) хеш-функции (обычно 32 байта для BLAKE3-256)
- **Constraint Root** - корень Merkle дерева для оценок constraint composition полиномов
  - Один корень для всех constraint полиномов
- **FRI Roots** - корни Merkle деревьев для каждого слоя FRI протокола
  - Количество корней = количество FRI слоев + 1 (для remainder)
  - Каждый корень - это хеш соответствующего слоя

### От чего зависит размер:
- **Размер хеша**: определяется хеш-функцией (BLAKE3-256 = 32 байта, BLAKE3-192 = 24 байта)
- **Количество сегментов трейса**: больше сегментов → больше trace roots
- **Количество FRI слоев**: зависит от:
  - Размера домена (trace_length × blowup_factor)
  - FRI folding factor (чем больше, тем меньше слоев)
  - FRI remainder max degree
- **Размер относительно небольшой** (обычно несколько сотен байт)

**Формула приблизительного размера:**
```
size ≈ (num_trace_segments + 1 + num_fri_layers + 1) × hash_size
```

---

## 3. Trace Queries (Запросы к трейсу)

### Что хранится:
Для каждого сегмента трейса:
- **Values** - фактические значения элементов поля в запрошенных позициях
  - Количество значений = num_queries × trace_width (для данного сегмента)
  - Каждое значение - это элемент поля (обычно 8 байт для f64)
- **Opening Proofs** - доказательства открытия (Merkle proofs) для этих значений
  - Batch Merkle proof для всех запрошенных позиций
  - Размер зависит от глубины дерева и количества запросов

### От чего зависит размер:
- **Количество запросов (num_queries)**: линейно влияет на размер
  - Больше запросов → больше values и больше узлов в opening proof
- **Ширина трейса (trace_width)**: больше колонок → больше значений на запрос
- **Размер домена (trace_length × blowup_factor)**: влияет на глубину Merkle дерева
  - Глубина = log₂(domain_size)
  - Больше домен → глубже дерево → больше узлов в proof
- **Размер элемента поля**: f64 = 8 байт, f128 = 16 байт
- **Blowup factor**: влияет косвенно через размер домена

**Формула приблизительного размера:**
```
values_size = num_queries × trace_width × element_size
opening_proof_size ≈ num_queries × log₂(domain_size) × hash_size
total_size = values_size + opening_proof_size
```

**Это один из самых больших компонентов**, особенно при большом количестве запросов и широком трейсе.

---

## 4. Constraint Queries (Запросы к constraint полиномам)

### Что хранится:
- **Values** - оценки constraint composition полиномов в запрошенных позициях
  - Количество значений = num_queries × num_constraint_composition_columns
  - num_constraint_composition_columns обычно равно blowup_factor
- **Opening Proofs** - batch Merkle proof для этих значений
  - Аналогично trace queries, но для constraint полиномов

### От чего зависит размер:
- **Количество запросов (num_queries)**: линейно влияет
- **Blowup factor**: определяет количество constraint composition колонок
  - Больше blowup → больше значений на запрос
- **Размер домена**: влияет на глубину Merkle дерева (как в trace queries)
- **Размер элемента поля**: зависит от field extension
  - FieldExtension::None → base field (8 байт для f64)
  - FieldExtension::Quadratic → extension field (16 байт для f64)
  - FieldExtension::Cubic → extension field (24 байта для f64)

**Формула приблизительного размера:**
```
values_size = num_queries × blowup_factor × element_size
opening_proof_size ≈ num_queries × log₂(domain_size) × hash_size
```

**Размер может быть значительным** при большом blowup_factor и field extension.

---

## 5. OOD Frame (Out-of-Domain Frame)

### Что хранится:
- **Trace States** - оценки всех trace полиномов в двух точках вне домена:
  - В точке z (out-of-domain point)
  - В точке z × g (где g - генератор домена трейса)
  - Для каждого полинома хранятся оба значения (current и next row)
  - Количество значений = 2 × trace_width (main + aux если есть)
- **Quotient States** - оценки constraint composition полиномов в тех же двух точках:
  - В точке z
  - В точке z × g
  - Количество значений = 2 × num_constraint_composition_columns

### От чего зависит размер:
- **Ширина трейса (trace_width)**: больше колонок → больше trace states
- **Blowup factor**: определяет количество constraint composition колонок
- **Размер элемента поля**: зависит от field extension
  - FieldExtension::None → base field
  - FieldExtension::Quadratic/Cubic → extension field (больше размер)
- **Наличие auxiliary trace**: если есть aux trace, добавляются дополнительные значения

**Формула приблизительного размера:**
```
trace_states_size = 2 × trace_width × element_size
quotient_states_size = 2 × blowup_factor × element_size
total_size = trace_states_size + quotient_states_size + metadata
```

**Размер относительно небольшой** (обычно несколько KB), но зависит от field extension.

---

## 6. FRI Proof (FRI доказательство)

### Что хранится:
FRI доказательство состоит из нескольких слоев и remainder:

#### FRI Layers (Слои):
Для каждого слоя:
- **Values** - оценки свернутого полинома в запрошенных позициях
  - Количество значений = num_queries × folding_factor
  - На каждом слое домен уменьшается в folding_factor раз
- **Opening Proofs** - batch Merkle proofs для этих значений
  - Размер зависит от глубины дерева на данном слое

#### Remainder (Остаток):
- **Coefficients** - коэффициенты полинома последнего слоя
  - Количество коэффициентов = remainder_max_degree + 1
  - Обычно remainder_max_degree = 127, значит 128 коэффициентов

### От чего зависит размер:
- **Количество FRI слоев**: зависит от:
  - Начального размера домена (trace_length × blowup_factor)
  - FRI folding factor (чем больше, тем меньше слоев)
  - FRI remainder max degree (определяет когда остановиться)
  
  Формула: `num_layers ≈ log_folding_factor(domain_size / remainder_max_degree)`

- **FRI folding factor**: влияет на:
  - Количество слоев (больше factor → меньше слоев)
  - Количество значений на запрос в каждом слое (больше factor → больше значений)

- **Количество запросов (num_queries)**: линейно влияет на размер каждого слоя

- **Размер домена**: влияет на глубину Merkle деревьев в каждом слое

- **FRI remainder max degree**: определяет размер remainder
  - Больше degree → больше коэффициентов в remainder

- **Размер элемента поля**: зависит от field extension

**Формула приблизительного размера:**
```
Для каждого слоя i:
  domain_size_i = domain_size / (folding_factor ^ i)
  values_size_i = num_queries × folding_factor × element_size
  proof_size_i ≈ num_queries × log₂(domain_size_i) × hash_size
  
remainder_size = (remainder_max_degree + 1) × element_size

total_size = sum(layer_sizes) + remainder_size + metadata
```

**Это обычно самый большой компонент доказательства**, особенно при большом количестве слоев и запросов.

---

## 7. POW Nonce (Proof-of-Work Nonce)

### Что хранится:
- **Nonce** - 64-битное число (8 байт), найденное через proof-of-work
  - Используется для "шлифовки" (grinding) seed для запросов
  - Позволяет контролировать, какие позиции будут запрошены

### От чего зависит размер:
- **Фиксированный размер**: всегда 8 байт
- **Не зависит от параметров протокола**

---

## 8. Num Unique Queries

### Что хранится:
- **Количество уникальных запросов** - u8 (1 байт)
  - Может отличаться от num_queries, если одна и та же позиция запрашивалась несколько раз

### От чего зависит размер:
- **Фиксированный размер**: всегда 1 байт

---

## Итоговая зависимость размеров от параметров

### Параметры, наиболее влияющие на размер:

1. **num_queries** (количество запросов):
   - Сильно влияет на: Trace Queries, Constraint Queries, FRI Proof
   - Линейная зависимость

2. **blowup_factor**:
   - Влияет на: размер домена → глубина деревьев → размер opening proofs
   - Влияет на: количество constraint composition колонок → размер Constraint Queries и OOD Frame
   - Влияет на: размер FRI домена → количество FRI слоев

3. **trace_width** (ширина трейса):
   - Влияет на: размер Trace Queries (values)
   - Влияет на: размер OOD Frame (trace states)

4. **trace_length** (длина трейса):
   - Влияет на: размер домена → глубина деревьев → размер opening proofs
   - Влияет на: количество FRI слоев

5. **folding_factor** (FRI):
   - Влияет на: количество FRI слоев (обратная зависимость)
   - Влияет на: количество значений на запрос в каждом FRI слое

6. **field_extension**:
   - Влияет на: размер элементов поля → размер всех компонентов с values
   - Quadratic: ×2, Cubic: ×3

7. **grinding_factor**:
   - Не влияет напрямую на размер, но влияет на время генерации POW nonce

### Типичное распределение размеров:

Для типичного SHA-256 доказательства:
- **FRI Proof**: 40-60% от общего размера
- **Trace Queries**: 20-30%
- **Constraint Queries**: 10-20%
- **OOD Frame**: 5-10%
- **Commitments**: 1-3%
- **Context, POW Nonce, Num Unique Queries**: < 1%

