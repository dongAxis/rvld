package utils

type MapSet[K comparable] struct {
	m map[K]struct{}
}

func NewMapSet[K comparable]() MapSet[K] {
	return MapSet[K]{
		m: make(map[K]struct{}),
	}
}

func (s MapSet[K]) Add(val K) {
	s.m[val] = struct{}{}
}

func (s MapSet[K]) Contains(val K) bool {
	_, ok := s.m[val]
	return ok
}
